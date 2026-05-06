import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
import requests
import functions_framework
from google.cloud import secretmanager
from googleapiclient.discovery import build
from google.auth import default
from openai import OpenAI

# --- 共通ユーティリティ ---
def get_secret(secret_id: str) -> str:
    """Secret Managerから機密情報を取得する"""
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.environ["GCP_PROJECT"]
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")

def get_sheets_service():
    """Google Sheets API サービスを取得する"""
    creds, _ = default(scopes=["https://www.googleapis.com/auth/spreadsheets"])
    return build("sheets", "v4", credentials=creds)

# --- 外部情報収集 (CISA KEV) ---
def fetch_kev():
    """CISA KEVから脆弱性リストを取得する"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
        return [
            {
                "source": "CISA_KEV",
                "published_at": v.get("dateAdded", ""),
                "title": v.get("shortDescription", ""),
                "product": v.get("product", ""),
                "cve": v.get("cveID", ""),
                "exploited_in_the_wild": "true",
            }
            for v in data.get("vulnerabilities", [])
        ]
    except Exception as e:
        print(f"Error fetching KEV: {e}")
        return []

# --- 資産突合ロジック ---
def load_asset_map(sheets, spreadsheet_id):
    """スプレッドシートから資産マップを読み込む"""
    result = sheets.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range="asset_map!A2:F"
    ).execute()
    rows = result.get("values", [])
    return [
        {
            "product_keyword": r[0].lower() if len(r) > 0 else "",
            "system_owner": r[2] if len(r) > 2 else "",
            "is_external": r[3].lower() == "true" if len(r) > 3 else False,
            "is_critical": r[4].lower() == "true" if len(r) > 4 else False,
        }
        for r in rows if r
    ]

def enrich_with_asset(record, asset_map):
    """脆弱性レコードに資産情報を付与する"""
    product_lower = record.get("product", "").lower()
    title_lower = record.get("title", "").lower()
    
    # キーワードマッチング
    matched = next((a for a in asset_map if a["product_keyword"] and (a["product_keyword"] in product_lower or a["product_keyword"] in title_lower)), None)
    
    record["asset_relevance"] = "high" if matched else "low"
    record.update({
        "owner": matched["system_owner"] if matched else "",
        "is_external": matched["is_external"] if matched else False,
        "is_critical": matched["is_critical"] if matched else False,
        "industry_relevance": "medium"
    })
    return record

def score_priority(record):
    """緊急度スコアを算出する"""
    if record.get("exploited_in_the_wild") == "true" and record.get("asset_relevance") == "high":
        if record.get("is_external") or record.get("is_critical"):
            return "high"
        return "medium"
    return "low"

# --- AI解析 (Structured Output使用) ---
def build_ai_summary(client, record):
    """OpenAIを使用して脆弱性を要約する"""
    schema = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "reason": {"type": "string"},
            "recommended_action": {"type": "string"}
        },
        "required": ["summary", "reason", "recommended_action"],
        "additionalProperties": False
    }
    prompt = f"以下の脆弱性情報を日本語で整理してください。情報源: {record['source']}, CVE: {record['cve']}, 製品: {record['product']}, タイトル: {record['title']}"
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_schema", "json_schema": {"name": "threat_summary", "schema": schema, "strict": True}}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"AI解析エラー: {e}")
        return {"summary": "解析失敗", "reason": "-", "recommended_action": "手動確認"}

def get_existing_ids(sheets, spreadsheet_id):
    """既に登録済みのID一覧を取得する"""
    try:
        result = sheets.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range="intel_queue!A2:A"
        ).execute()
        return {r[0] for r in result.get("values", []) if r}
    except Exception:
        return set()

def send_slack(webhook_url, payload_body):
    """Slackへリッチなメッセージを送信する"""
    requests.post(webhook_url, json=payload_body, timeout=15)

# --- メイン関数 ---
@functions_framework.http
def main(request):
    spreadsheet_id = get_secret("SPREADSHEET_ID")
    slack_webhook = get_secret("SLACK_WEBHOOK_URL")
    openai_client = OpenAI(api_key=get_secret("OPENAI_API_KEY"))
    
    sheets = get_sheets_service()
    asset_map = load_asset_map(sheets, spreadsheet_id)
    existing_ids = get_existing_ids(sheets, spreadsheet_id)
    
    records = fetch_kev()
    output_rows = []
    now_utc = datetime.now(timezone.utc)
    now_jst_str = now_utc.astimezone(timezone(timedelta(hours=9))).strftime('%Y-%m-%d %H:%M')
    
    for r in records:
        # 重複チェック用のハッシュ作成
        digest = hashlib.sha256(f"{r['source']}|{r['cve']}".encode()).hexdigest()[:16]
        if digest in existing_ids:
            continue
            
        enriched = enrich_with_asset(r, asset_map)
        enriched["priority"] = score_priority(enriched)
        
        # 資産に関連がある場合のみAI解析を実行
        if enriched["asset_relevance"] == "high":
            ai_result = build_ai_summary(openai_client, enriched)
            enriched.update(ai_result)
            
            # Slack通知 (High/Mediumのみ)
            payload = {
                "attachments": [{
                    "color": "#eb4034" if enriched["priority"] == "high" else "#f29541",
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": "🚨 資産関連の脆弱性を検知"}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": f"*製品:* `{enriched['product']}`\n*CVE:* <https://nvd.nist.gov/vuln/detail/{enriched['cve']}|{enriched['cve']}>"}},
                        {"type": "section", "fields": [
                            {"type": "mrkdwn", "text": f"*優先度:*\n{enriched['priority'].upper()}"},
                            {"type": "mrkdwn", "text": f"*担当者:*\n{enriched['owner'] or '未割当'}"}
                        ]},
                        {"type": "section", "text": {"type": "mrkdwn", "text": f"*要約:*\n{enriched.get('summary', '解析なし')}"}},
                        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"📍 *推奨対応:* {enriched.get('recommended_action', '確認してください')}"}]}
                    ]
                }]
            }
            send_slack(slack_webhook, payload)
        else:
            enriched.update({
                "summary": "資産非該当のため解析スキップ",
                "reason": "Low Relevance",
                "recommended_action": "-"
            })
        
        # 書き込み用リストに追加
        output_rows.append([
            digest, enriched["source"], enriched["published_at"], enriched["title"],
            enriched["product"], enriched["cve"], enriched["exploited_in_the_wild"],
            enriched["asset_relevance"], enriched["industry_relevance"], enriched["priority"],
            enriched["summary"], enriched["reason"], enriched["recommended_action"],
            enriched["owner"], "new", now_utc.isoformat(), now_utc.isoformat()
        ])
    
    # スプレッドシートへの書き込み処理
    if output_rows:
        chunk_size = 100
        for i in range(0, len(output_rows), chunk_size):
            sheets.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id, range="intel_queue!A2",
                valueInputOption="RAW", insertDataOption="INSERT_ROWS",
                body={"values": output_rows[i : i + chunk_size]}
            ).execute()
    else:
        # 新着なし時のヘルスチェック通知 (JST)
        health_payload = {
            "attachments": [{
                "color": "#36a64f",
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": f"✅ *定期チェック完了*: {now_jst_str}\n新たな脆弱性は見つかりませんでした。正常稼働中です。"}}
                ]
            }]
        }
        send_slack(slack_webhook, health_payload)
        
    return {"status": "ok", "appended": len(output_rows)}