"""深度分析消费者（deep_analyze_consumer）——2026-08-28 合并社区方案

官方"深度分析"依赖外部 Hermes agent 消费队列，但消费者从未提供。
本进程补位：轮询 pending → 等上下文就绪（防竞态）→ 调 OpenAI 兼容 API → 写 done。

部署：python deep_analyze_consumer.py（或 systemd 常驻）
环境变量（.env）：DEEPSEEK_API_KEY / DEEPSEEK_BASE_URL / DEEPSEEK_MODEL
"""
import json, os, sys, time
from pathlib import Path
from datetime import datetime

import httpx

BASE_DIR = Path(__file__).resolve().parent

# 轻量 .env 加载（同目录 .env——key=value 行；不覆盖已存在的环境变量）
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

HERMES_QUEUE = BASE_DIR / "hermes_queue"
HERMES_PENDING = HERMES_QUEUE / "pending"
HERMES_DONE = HERMES_QUEUE / "done"
HERMES_QUICK = HERMES_QUEUE / "quick"
CONTEXT_DIR = HERMES_QUEUE / "context"

API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

POLL_INTERVAL = 3.0   # 轮询秒数
MAX_CONTEXT_CHARS = 60000  # 上下文截断上限（防超长）

SYSTEM_PROMPT = (
    "你是联想售后日志诊断专家。根据提供的日志上下文与用户问题，给出结构化诊断结论。"
    "输出格式：先用简短结论，再列关键证据（引用日志中的实际数据），最后给排查方向。"
    "只陈述日志中观察到的事实，不要编造数据，不要给更换硬件的建议。"
)


def resolve_context(payload: dict, rid: str):
    """返回 (context_text, None) 或 (None, 未就绪原因)。上下文未就绪 → 跳过等待（不删 pending）。"""
    # 优先 payload.preprocessed_context（路径）
    pc = payload.get("preprocessed_context")
    if pc:
        p = Path(pc)
        if p.exists() and p.stat().st_size > 0:
            try:
                return p.read_text(encoding="utf-8", errors="replace")[:MAX_CONTEXT_CHARS], None
            except Exception:
                pass
        return None, "preprocessed_context 文件未就绪"
    # 兜底 context/{rid}.txt
    cf = CONTEXT_DIR / f"{rid}.txt"
    if cf.exists() and cf.stat().st_size > 0:
        try:
            return cf.read_text(encoding="utf-8", errors="replace")[:MAX_CONTEXT_CHARS], None
        except Exception:
            pass
    return None, "上下文未就绪（后台预处理中）——等待"


def call_llm(context: str, message: str) -> str:
    """调 AI API（多通道自动故障切换——② 备用 AI 通道）。
    主 → 备，每通道最多 2 次；content 非空为成功；全部失败返回错误摘要（不抛——写 done 不卡队列）。"""
    if not API_KEY:
        return "【深度分析不可用】未配置 DEEPSEEK_API_KEY 环境变量。"
    backup_key = os.getenv("DEEPSEEK_API_KEY_2", "").strip()
    backup_url = os.getenv("DEEPSEEK_BASE_URL_2", "").strip().rstrip("/")
    backup_model = os.getenv("DEEPSEEK_MODEL_2", "").strip() or MODEL
    channels = [{"key": API_KEY, "url": BASE_URL, "model": MODEL}]
    if backup_key and backup_url:
        channels.append({"key": backup_key, "url": backup_url, "model": backup_model})

    errors = []
    for ch in channels:
        for attempt in range(2):
            try:
                payload = {
                    "model": ch["model"],
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"===== 日志上下文 =====\n{context}\n\n===== 用户问题 =====\n{message}"},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 8000,
                }
                resp = httpx.post(f"{ch['url']}/chat/completions", json=payload, timeout=180,
                                  headers={"Authorization": f"Bearer {ch['key']}"})
                resp.raise_for_status()
                content = (resp.json()["choices"][0]["message"].get("content") or "").strip()
                if content:
                    return content  # ✅ 成功出口
                errors.append(f"{ch['url']}: 空回复(第{attempt+1}次)")
            except Exception as e:
                errors.append(f"{ch['url']}: {str(e)[:120]}(第{attempt+1}次)")
    return f"【深度分析失败】AI 分析所有通道均失败: {'; '.join(errors)}"


def process_request(rid: str):
    """处理单个 pending 请求。上下文未就绪 → 跳过（保持 pending）。"""
    pf = HERMES_PENDING / f"{rid}.json"
    try:
        payload = json.loads(pf.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[consumer] {rid} payload 读取失败: {e}——跳过")
        return

    context, reason = resolve_context(payload, rid)
    if context is None:
        print(f"[consumer] {rid} {reason}——跳过本轮（不删 pending）")
        return

    message = payload.get("message", "请分析这份日志")
    try:
        print(f"[consumer] {rid} 上下文就绪（{len(context)} 字符）——调用 {MODEL} ...")
        reply = call_llm(context, message)
    except Exception as e:
        reply = f"【深度分析失败】{e}"
        print(f"[consumer] {rid} API 调用失败: {e}——写失败结果")

    HERMES_DONE.mkdir(parents=True, exist_ok=True)
    done_file = HERMES_DONE / f"{rid}.json"
    done_file.write_text(json.dumps({"reply": reply, "completed_at": datetime.now().isoformat()},
                                    ensure_ascii=False), encoding="utf-8")
    # 清理
    try:
        pf.unlink(missing_ok=True)
    except Exception:
        pass
    print(f"[consumer] {rid} 完成——done/{rid}.json（{len(reply)} 字符）")


def main():
    HERMES_PENDING.mkdir(parents=True, exist_ok=True)
    HERMES_DONE.mkdir(parents=True, exist_ok=True)
    print(f"[consumer] 深度分析消费者启动——轮询 {HERMES_PENDING}（{MODEL}）")
    while True:
        try:
            files = sorted(HERMES_PENDING.glob("*.json"))
            for pf in files:
                process_request(pf.stem)
        except Exception as e:
            print(f"[consumer] 主循环异常: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[consumer] 已停止")
