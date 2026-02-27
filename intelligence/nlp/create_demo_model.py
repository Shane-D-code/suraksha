"""
Script to create demo ML models for PhishGuard.
This generates the phish_model.joblib and tfidf_vectorizer.joblib files.
"""
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

# Create sample training data
phishing_texts = [
    "Urgent! Verify your account immediately or it will be suspended",
    "Your account has been compromised. Click here to verify",
    "Verify your identity now to avoid account suspension",
    "Urgent action required: Update your payment information",
    "Your account will be locked in 24 hours",
    "Click here to reset your password immediately",
    "Congratulations! You've won a prize. Claim now",
    "Security alert: Unauthorized access detected",
    "Confirm your account details to continue",
    "Limited time offer: Verify your account now",
    "Your Netflix account has been suspended",
    "Apple ID verification required immediately",
    "Amazon: Order confirmation - click to view",
    "Bank account verification needed urgent",
    "Your account shows unusual activity",
    "Verify your PayPal account to continue",
    "IRS: Tax refund waiting for you",
    "FedEx: Package delivery failed - click to reschedule",
    "Microsoft: Your password expires in 24 hours",
    "Social security number verification required"
]

normal_texts = [
    "Hey, are we still meeting tomorrow?",
    "Thanks for the invoice, I'll process it",
    "Can you send me the report when you have time?",
    "The project is on track for completion",
    "Please review the attached document",
    "Let's schedule a call for next week",
    "Great work on the presentation",
    "I'll be out of office next Monday",
    "The meeting has been rescheduled to 3pm",
    "Thanks for your help with the project",
    "Just following up on my previous email",
    "Could you please clarify the requirements?",
    "The client approved the proposal",
    "I'll send the files later today",
    "Happy birthday! Hope you have a great day",
    "The server maintenance is scheduled for tonight",
    "Please update your calendar with the new dates",
    "I've uploaded the files to the shared drive",
    "The quarterly report looks good",
    "Let me know if you need any additional information"
]

# Combine data
all_texts = phishing_texts + normal_texts
labels = [1] * len(phishing_texts) + [0] * len(normal_texts)

# Create TF-IDF vectorizer
vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    stop_words='english'
)

# Fit and transform
X = vectorizer.fit_transform(all_texts)

# Create Logistic Regression model
base_model = LogisticRegression(max_iter=1000, C=1.0, random_state=42)

# Calibrate for probability estimates
calibrated_model = CalibratedClassifierCV(base_model, cv=3)
calibrated_model.fit(X, labels)

# Create pipeline
pipeline = Pipeline([
    ('vectorizer', vectorizer),
    ('clf', calibrated_model)
])

# Save the model
output_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(output_dir, "phish_model.joblib")
joblib.dump(pipeline, model_path)
print(f"✅ ML model saved to: {model_path}")

# Also save standalone vectorizer for predictor.py
vectorizer_path = os.path.join(output_dir, "tfidf_vectorizer.joblib")
joblib.dump(vectorizer, vectorizer_path)
print(f"✅ Vectorizer saved to: {vectorizer_path}")

# Test the model
test_phishing = "Verify your account immediately to avoid suspension"
test_normal = "Thanks for the meeting confirmation"

prob_phish = pipeline.predict_proba([test_phishing])[0][1]
prob_normal = pipeline.predict_proba([test_normal])[0][1]

print(f"\n📊 Test Results:")
print(f"   Phishing text → {prob_phish:.3f} ({'PHISHING' if prob_phish > 0.5 else 'SAFE'})")
print(f"   Normal text → {prob_normal:.3f} ({'PHISHING' if prob_normal > 0.5 else 'SAFE'})")

