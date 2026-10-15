import joblib
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Sample training feature extractor & synthetic dataset for initial build
# Features: [url_len, domain_len, count_dots, count_hyphens, is_ip, count_at, has_https, num_subdomains]

X_train = np.array([
    [15, 11, 2, 0, 0, 0, 1, 1],  # safe
    [120, 45, 5, 3, 1, 1, 0, 4], # phishing
    [22, 14, 2, 0, 0, 0, 1, 1],  # safe
    [95, 38, 4, 2, 0, 1, 0, 3],  # phishing
    [18, 12, 1, 0, 0, 0, 1, 1],  # safe
    [110, 50, 6, 4, 1, 0, 0, 5]  # phishing
])

y_train = np.array([0, 1, 0, 1, 0, 1])  # 0: Safe, 1: Phishing

clf = RandomForestClassifier(n_estimators=10, random_state=42)
clf.fit(X_train, y_train)

joblib.dump(clf, 'phishing_model.pkl')
print("✅ ML Model trained and saved as 'phishing_model.pkl'")
