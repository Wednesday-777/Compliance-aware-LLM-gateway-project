import os

import httpx
import pandas as pd
import streamlit as st

st.set_page_config(page_title="LLM Gateway Dashboard", layout="wide")
st.title("Compliance-Aware LLM Gateway")

# Sidebar: connection settings
with st.sidebar:
    st.header("Connection")
    base_url = st.text_input("Gateway URL", os.getenv("GATEWAY_URL", "http://127.0.0.1:8000"))
    admin_key = st.text_input(
        "Admin API key", value=os.getenv("GATEWAY_ADMIN_KEY", ""), type="password"
    )
    limit = st.slider("Recent entries to load", 20, 200, 100, step=20)
    st.button("Refresh data")  # any click reruns the script, which reloads the data

base_url = base_url.rstrip("/")


def fetch(path: str, params: dict | None = None):
    r = httpx.get(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {admin_key}"},
        params=params,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


tab_overview, tab_events, tab_try = st.tabs(["Overview", "Recent events", "Try the gateway"])

# Tab 3: send a message through the gateway
with tab_try:
    st.write("Send a message through the gateway and see what it does with it.")
    st.caption("Use a **client** key here. Use fake data only (no real personal information).")
    client_key = st.text_input(
        "Client API key", value=os.getenv("GATEWAY_CLIENT_KEY", ""), type="password"
    )
    prompt = st.text_area(
        "Message",
        "My PAN is ABCDE1234F. Explain in two sentences why PAN is needed for taxes.",
    )
    if st.button("Send through gateway"):
        if not client_key:
            st.warning("Enter a client API key first.")
        else:
            try:
                r = httpx.post(
                    f"{base_url}/v1/chat",
                    headers={"Authorization": f"Bearer {client_key}"},
                    json={"messages": [{"role": "user", "content": prompt}]},
                    timeout=60,
                )
            except httpx.RequestError:
                st.error("Cannot reach the gateway. Is it running, and is the URL right?")
            else:
                data = r.json()
                if r.status_code == 200:
                    st.success("Allowed")
                    st.write(data["reply"])
                    st.caption(
                        f"PII redacted before reaching the LLM: "
                        f"{data['pii_redacted'] or 'none'} · request {data['request_id']}"
                    )
                else:
                    st.error(f"Rejected (HTTP {r.status_code})")
                    st.json(data.get("detail", data))

# Load data for the other tabs
if not admin_key:
    with tab_overview:
        st.info("Enter an admin API key in the sidebar to see the dashboard.")
    st.stop()

try:
    stats = fetch("/audit/stats")
    entries = fetch("/audit/recent", {"limit": limit})
except httpx.HTTPStatusError as e:
    code = e.response.status_code
    msg = {401: "The gateway rejected this key.", 403: "This key is not an admin key."}.get(
        code, f"The gateway returned HTTP {code}."
    )
    with tab_overview:
        st.error(msg)
    st.stop()
except httpx.RequestError:
    with tab_overview:
        st.error("Cannot reach the gateway. Is it running, and is the URL right?")
    st.stop()

df = pd.DataFrame(entries)
outcomes = stats["outcomes"]


def bar(title: str, data: dict) -> None:
    st.subheader(title)
    if data:
        st.bar_chart(pd.Series(data))
    else:
        st.caption("Nothing yet.")


# Tab 1: overview
with tab_overview:
    chat_total = sum(v for k, v in outcomes.items() if k not in ("unauthorized", "forbidden"))
    blocked = stats["blocked"]
    allowed_latency = df.loc[df["outcome"] == "allowed", "latency_ms"] if not df.empty else []

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Chat requests", chat_total)
    c2.metric("Blocked", blocked)
    c3.metric("Block rate", f"{blocked / chat_total:.0%}" if chat_total else "n/a")
    c4.metric("Auth failures", outcomes.get("unauthorized", 0) + outcomes.get("forbidden", 0))
    c5.metric(
        "Avg LLM latency",
        f"{allowed_latency.mean():.0f} ms" if len(allowed_latency) else "n/a",
    )

    left, right = st.columns(2)
    with left:
        bar("Outcomes", outcomes)
        bar("Why requests were blocked", stats["block_reasons"])
    with right:
        bar("Sensitive data types seen", stats["pii_counts"])
        bar("Requests by client", stats["by_client"])

    st.subheader("Requests over time")
    if df.empty:
        st.caption("No log entries yet.")
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
        bucket = st.selectbox(
            "Group by",
            ["min", "h", "D"],
            index=1,
            format_func={"min": "Minute", "h": "Hour", "D": "Day"}.get,
        )
        series = (
            df.groupby([pd.Grouper(key="timestamp", freq=bucket), "outcome"])
            .size()
            .unstack(fill_value=0)
        )
        st.bar_chart(series)

# Tab 2: recent events
with tab_events:
    if df.empty:
        st.info("No log entries yet. Send some requests first.")
    else:
        view = df.copy()
        view["timestamp"] = pd.to_datetime(view["timestamp"], utc=True, format="ISO8601")
        for col in ("pii_redacted", "pii_blocked", "injection_rules"):
            view[col] = view[col].apply(lambda xs: ", ".join(xs))

        wanted = st.multiselect(
            "Show outcomes",
            sorted(view["outcome"].unique()),
            default=sorted(view["outcome"].unique()),
        )
        view = view[view["outcome"].isin(wanted)]
        columns = [
            "timestamp", "outcome", "block_reason", "client", "pii_redacted",
            "pii_blocked", "injection_score", "injection_rules", "latency_ms", "request_id",
        ]
        st.dataframe(view[columns], hide_index=True)
        st.caption("The log stores metadata only: no prompts, replies or personal data.")