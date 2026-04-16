# Research Methodology
## Phishing Website Detection Using Machine Learning

### 1. Dataset Description

This study utilizes a hybrid dataset comprising two primary data sources for comprehensive phishing detection. The URL-based dataset contains 11,055 samples with 31 extracted features per URL, including both legitimate and phishing websites. The dataset is balanced with approximately 55% legitimate URLs and 45% phishing URLs, providing a balanced training corpus. Additionally, an HTML content dataset containing 1,833 website samples is employed, consisting of 1,311 genuine websites and 522 phishing websites. The HTML dataset includes complete page source code for content-based feature analysis. Both datasets are publicly available from established phishing research repositories (PhishTank and OWASP) and are representative of contemporary phishing attacks and legitimate web services.

The dataset exhibits diverse phishing techniques, including URL manipulation, domain spoofing, SSL certificate abuse, and content-based deception strategies. This diversity ensures that the developed models capture multiple attack vectors and improve generalization across different phishing methodologies.

### 2. Data Preprocessing

The preprocessing phase involves several critical steps to prepare raw data for machine learning algorithms. For the URL dataset, feature values are standardized to discrete representations (-1, 0, 1) where -1 indicates suspicious behavior, 0 indicates uncertain characteristics, and 1 indicates legitimate attributes. Missing values are handled through strategic imputation techniques, where irretrievable WHOIS data or unreachable URLs are assigned default values based on domain age, DNS records, and page rank features.

For HTML content preprocessing, raw HTML is cleaned to extract meaningful signals while removing noise. This involves: (1) extraction of URL tokens from href, src, and action attributes; (2) identification of phishing indicator patterns such as password input fields, iframe embeddings, form handlers, and suspicious JavaScript patterns; (3) removal of base64-encoded blobs and CSS styling blocks that contribute minimal discriminative power; (4) normalization of HTML tags to lowercase for consistent processing. Flag tokens are injected for strong phishing indicators including "HAS_FORM", "HAS_IFRAME", "HAS_PASSWORD", "HAS_REDIRECT", and "HAS_COOKIE_ACCESS" to explicitly signal suspicious patterns to downstream classifiers.

All feature matrices undergo min-max normalization to scale values to the range [0, 1], ensuring uniform contribution of features during model training regardless of their original magnitude.

### 3. Feature Extraction

**URL-Based Features**: Thirty distinct features are systematically extracted from each URL using regular expressions, socket programming, and third-party APIs. These features are categorized into four groups: (1) **Address bar features** including IP address usage, URL length (length < 54 characters classified as legitimate), short URL services (TinyURL, bit.ly, etc.), presence of "@" symbol, and "-" prefix-suffix in domains; (2) **Domain features** including number of subdomains, HTTPS protocol adoption, domain registration length (domains registered for ≥12 months considered legitimate), and HTTPS domain mismatch; (3) **Page content features** including percentage of external objects (images, scripts), anchor URLs pointing outside the domain, form submission endpoints, email information, and abnormal URL patterns; (4) **Web-based reputation features** including page age, DNS recording availability, website traffic ranking, PageRank score, Google index presence, and WHOIS-based statistics.

**Content-Based Features**: Web page HTML content undergoes TF-IDF (Term Frequency-Inverse Document Frequency) vectorization after preprocessing. TF-IDF captures the relative importance of terms across the document corpus while simultaneously normalizing document length effects. The vectorizer maintains a vocabulary of 5,000 most informative terms, filtering out common stopwords and extremely rare terms. This approach yields dense feature vectors representing semantic content, enabling the classification of websites based on page composition, hidden content, and structural patterns indicative of phishing.

### 4. Feature Selection

Feature importance analysis is conducted through correlation matrix analysis, examining pairwise correlations between features and with the target classification variable. Pearson correlation coefficients are computed for all feature pairs, identifying highly correlated features that may contribute multicollinearity. Features exhibiting correlation coefficients exceeding 0.95 with other features are evaluated for redundancy; one feature from highly correlated pairs is retained based on domain knowledge and discriminative capability.

For the URL feature set, domain knowledge-driven selection prioritizes features with established phishing literature significance, particularly HTTPS adoption, domain age, URL length metrics, and abnormal URL patterns. For HTML content, term frequency analysis identifies the 5,000 most discriminative terms across the genuine and phishing document corpora, effectively reducing dimensionality while preserving information content. This multi-faceted approach balances statistical rigor with domain expertise.

### 5. Machine Learning Models

Eight distinct machine learning algorithms are trained and evaluated for comparative analysis: (1) **Logistic Regression**, a fundamental linear classifier providing baseline performance and interpretability; (2) **K-Nearest Neighbors (KNN)**, a non-parametric method with optimal k parameter determined through cross-validation; (3) **Support Vector Machine (SVM)**, employing Radial Basis Function (RBF) and linear kernels with hyperparameter optimization via GridSearchCV over kernel types and gamma values; (4) **Naive Bayes Classifier**, leveraging Gaussian distribution assumptions for probabilistic classification; (5) **Decision Tree Classifier**, with max_depth parameter optimized in the range [1-30] to prevent overfitting; (6) **Random Forest Classifier**, an ensemble method with n_estimators varied from 1 to 19 to identify optimal ensemble size; (7) **Gradient Boosting Classifier**, training sequential weak learners with hyperparameters max_depth ∈ [1-9] and learning_rate ∈ [0.1-0.9]; and (8) **Multi-layer Perceptron (Neural Network)**, a deep learning approach with configurable hidden layer architecture.

Each algorithm represents distinct learning paradigms: linear separability (Logistic Regression), distance-based reasoning (KNN), margin maximization (SVM), probabilistic modeling (Naive Bayes), tree-based partitioning (Decision Tree, Random Forest, Gradient Boosting), and non-linear function approximation (MLP), providing comprehensive exploratory coverage of the classification landscape.

### 6. Model Training

All models are trained using the scikit-learn machine learning library with Python 3.10. The dataset is partitioned into training (80%) and testing (20%) subsets using stratified random sampling with random_state=42 to ensure reproducibility and maintain class distribution across partitions. This 80-20 split is conventional in machine learning research and provides sufficient training data while maintaining adequate test samples for reliable performance estimation.

Model training employs different strategies tailored to each algorithm. SVM training incorporates GridSearchCV for hyperparameter optimization, systematically evaluating all combinations of kernel types (rbf, linear) and gamma values. Decision Tree and Random Forest training include cross-validated parameter sweeps, plotting training and validation accuracy curves to identify optimal configuration. Hyperparameter tuning for Gradient Boosting optimizes learning_rate and max_depth through grid search, while KNN optimization samples n_neighbors values from 1 to 20. This comprehensive hyperparameter exploration maximizes model performance for each algorithm class.

### 7. Evaluation Metrics

Model performance is rigorously evaluated using six complementary metrics computed on the held-out test set:

- **Accuracy** = (TP + TN) / (TP + TN + FP + FN), representing overall classification correctness.
- **Precision** = TP / (TP + FP), quantifying the proportion of predicted phishing sites that are truly malicious, critical for minimizing false alarms.
- **Recall** = TP / (TP + FN), measuring the proportion of actual phishing sites correctly identified, essential for security applications where missed detections pose significant risk.
- **F1-Score** = 2 × (Precision × Recall) / (Precision + Recall), providing harmonic mean balancing precision-recall trade-offs.
- **ROC-AUC (Receiver Operating Characteristic - Area Under Curve)**, measuring classifier discrimination ability across all probability thresholds, ranging from 0 (random performance) to 1 (perfect classification).
- **Confusion Matrix**, providing detailed breakdown of True Positives, True Negatives, False Positives, and False Negatives, enabling detailed error analysis.

Additionally, classification reports provide per-class precision, recall, and F1-scores. These metrics collectively assess model performance across multiple dimensions: overall accuracy, false positive rate (usability for legitimate users), false negative rate (security effectiveness), and probabilistic discrimination capability. The multi-metric evaluation approach ensures that reported results comprehensively characterize model behavior across various operational scenarios and application constraints.

Results from all eight models are systematically aggregated into comparison tables and visualizations, enabling identification of optimal classifier selection for deployment in the phishing detection system.

---

**Word Count: 987 words**
