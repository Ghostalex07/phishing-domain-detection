# 🔐 Phishing Domain Detection

A Machine Learning project focused on detecting malicious (phishing)
domains using domain-based lexical and structural features.

------------------------------------------------------------------------

## 📌 Project Overview

Phishing attacks remain one of the most common cybersecurity threats.\
This project aims to detect phishing domains using machine learning
techniques by analyzing domain name characteristics and patterns.

The system classifies domains into:

-   ✅ Legitimate\
-   ⚠️ Phishing

This project demonstrates practical application of data preprocessing,
feature engineering, and classification modeling in cybersecurity.

------------------------------------------------------------------------

## 🎯 Objectives

-   Identify suspicious domain patterns
-   Engineer meaningful domain-based features
-   Train and evaluate classification models
-   Provide a reusable pipeline for phishing detection

------------------------------------------------------------------------

## 🧠 Technologies & Tools

-   **Python**
-   **Pandas**
-   **NumPy**
-   **Scikit-learn**
-   **Matplotlib**
-   **Seaborn**

------------------------------------------------------------------------

## 📊 Project Workflow

### 1️⃣ Data Loading

-   Import dataset containing domain names and labels

### 2️⃣ Data Preprocessing

-   Clean missing values
-   Normalize domain strings
-   Prepare structured data format

### 3️⃣ Feature Engineering

Examples of extracted features: - Domain length - Number of dots -
Presence of hyphens - Use of suspicious keywords - Numeric character
ratio - Special character patterns

### 4️⃣ Model Training

-   Train classification algorithms (e.g., Logistic Regression, Random
    Forest, etc.)
-   Split dataset into training and testing sets

### 5️⃣ Model Evaluation

Evaluate performance using: - Accuracy - Precision - Recall - F1-score -
Confusion Matrix

### 6️⃣ Prediction

-   Classify new unseen domains
-   Output predicted class (Legitimate / Phishing)

------------------------------------------------------------------------

## 🚀 How to Run the Project

### 1. Clone the repository

``` bash
git clone https://github.com/Ghostalex07/phishing-domain-detection.git
cd phishing-domain-detection
```

### 2. Install dependencies

``` bash
pip install -r requirements.txt
```

### 3. Run the main script

``` bash
python main.py
```

------------------------------------------------------------------------

## 📈 Example Output

    Domain: secure-login-paypal-update.com
    Prediction: Phishing ⚠️
    Confidence: 0.94

------------------------------------------------------------------------

## 🛡️ Why Domain-Based Detection?

Many phishing websites use domain manipulation techniques such as:

-   Typosquatting
-   Brand impersonation
-   Excessive subdomains
-   Suspicious keywords
-   Randomized character strings

By analyzing these patterns, machine learning models can effectively
detect potential threats before users access malicious content.

------------------------------------------------------------------------

## 📂 Project Structure

    phishing-domain-detection/
    │
    ├── data/
    ├── notebooks/
    ├── main.py
    ├── requirements.txt
    └── README.md

------------------------------------------------------------------------

## 📚 Learning Outcomes

This project demonstrates:

-   Applied machine learning in cybersecurity
-   Feature engineering techniques
-   Model evaluation best practices
-   Practical Git & GitHub workflow

------------------------------------------------------------------------

## 👤 Author

**Alex Blanco**\
GitHub: https://github.com/Ghostalex07

------------------------------------------------------------------------

## 📜 License

This project is intended for educational and research purposes.
