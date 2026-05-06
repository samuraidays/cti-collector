# CTI Collector

CISA KEV情報と資産リストをマッチングし、脆弱性トリアージを行う

## デプロイ

```
gcloud functions deploy ti-collector \
--gen2 \
--runtime python312 \
--region asia-northeast1 \
--source=. \
--entry-point=main \
--trigger-http \
--no-allow-unauthenticated \
--service-account=ti-collector@$(gcloud config get-value project).iam.gserviceaccount.com \
--set-env-vars=GCP_PROJECT=$(gcloud config get-value project) \
--memory=512Mi \
--timeout=3600s
```

## テスト

```
curl -X GET "https://asia-northeast1-$(gcloud config get-value project).cloudfunctions.net/ti-collector" \
-H "Authorization: Bearer $(gcloud auth print-identity-token)"
```