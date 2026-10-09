from ml.inference import analyze
import json

samples = [
    {
        "text": "Your KYC will expire today. Verify your PAN and OTP immediately at https://sbi-kyc-update.example.com",
        "urls": ["https://sbi-kyc-update.example.com"]
    },
    {
        "text": "Congratulations! You won a lottery prize of Rs 25 lakh. Pay processing fee to claim now.",
        "urls": []
    },
    {
        "text": "Your parcel is held. Pay Rs 25 to reschedule delivery: https://delivery-refund.example.com",
        "urls": ["https://delivery-refund.example.com"]
    },
]

for i, s in enumerate(samples, 1):
    print(f"\n--- SAMPLE {i} ---")
    print(json.dumps(analyze(**s), indent=2))
