import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use a non-GUI backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import time

# Step 1: Load the dataset
print("Loading dataset...")
df = pd.read_csv('preprocessed_etdf.csv')  # Ensure the file is in the same directory

# Step 2: Data Cleaning
print("\nStep 2: Data Cleaning")
print("Missing values before cleaning:")
print(df.isnull().sum())

# Handle missing values
df['rolling_avg_src_bytes'].fillna(df['rolling_avg_src_bytes'].mean(), inplace=True)
df['rolling_avg_dst_bytes'].fillna(df['rolling_avg_dst_bytes'].mean(), inplace=True)

# Convert categorical columns to the correct data type
df['protocol'] = df['protocol'].astype('category')
df['service'] = df['service'].astype('category')
df['flag'] = df['flag'].astype('category')

print("\nMissing values after cleaning:")
print(df.isnull().sum())

# Step 3: Exploratory Data Analysis (EDA)
print("\nStep 3: Exploratory Data Analysis (EDA)")
print("Summary Statistics:")
print(df.describe())

# Generate a unique timestamp for this run
timestamp = time.strftime("%Y%m%d_%H%M%S")

# Save the histogram plot
print("\nSaving histogram plot...")
df.hist(figsize=(20, 15), bins=30)
plt.savefig(f'histogram_{timestamp}.png', dpi=300, bbox_inches='tight')  # High-quality PNG
plt.close()

# Calculate the correlation matrix
corr_matrix = df.corr()

# Save the correlation matrix as a CSV file
print("Saving correlation matrix as CSV...")
corr_matrix.to_csv(f'correlation_matrix_{timestamp}.csv')  # Save as CSV

# Display the correlation matrix as a text-based table
print("\nCorrelation Matrix (Text-Based Table):")
print(corr_matrix)

# Save the correlation matrix as a text file
print("Saving correlation matrix as text file...")
with open(f'correlation_matrix_{timestamp}.txt', 'w') as f:
    f.write("Correlation Matrix:\n")
    f.write(corr_matrix.to_string())  # Save as text file

# Step 4: Feature Engineering
print("\nStep 4: Feature Engineering")
# Create a new feature for total bytes
df['total_bytes'] = df['src_bytes'] + df['dst_bytes']

# One-hot encode categorical variables
df = pd.get_dummies(df, columns=['protocol', 'service', 'flag'], drop_first=True)

# Normalize numerical features
scaler = StandardScaler()
numerical_features = ['src_bytes', 'dst_bytes', 'count', 'total_bytes']
df[numerical_features] = scaler.fit_transform(df[numerical_features])

# Step 5: Split the Data into Training and Testing Sets
print("\nStep 5: Splitting Data into Training and Testing Sets")
X = df.drop(columns=['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Train a Machine Learning Model
print("\nStep 6: Training a Random Forest Classifier")
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Step 7: Evaluate the Model
print("\nStep 7: Evaluating the Model")
y_pred = model.predict(X_test)

print("\nModel Evaluation:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, average='weighted'))
print("Recall:", recall_score(y_test, y_pred, average='weighted'))
print("F1-Score:", f1_score(y_test, y_pred, average='weighted'))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the confusion matrix plot
print("Saving confusion matrix plot...")
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.savefig(f'confusion_matrix_{timestamp}.png', dpi=300, bbox_inches='tight')  # High-quality PNG
plt.close()

# Step 8: Optimize the Model
print("\nStep 8: Optimizing the Model with Grid Search")
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5, 10]
}

grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, scoring='accuracy')
grid_search.fit(X_train, y_train)

print("\nBest Parameters:", grid_search.best_params_)
best_model = grid_search.best_estimator_

# Evaluate the optimized model
y_pred_optimized = best_model.predict(X_test)
print("Optimized Accuracy:", accuracy_score(y_test, y_pred_optimized))

# Step 9: Feature Importance
print("\nStep 9: Analyzing Feature Importance")
try:
    feature_importances = pd.Series(best_model.feature_importances_, index=X.columns)
    feature_importances.sort_values(ascending=False).plot(kind='bar', figsize=(12, 6))
    plt.title('Feature Importance')
    plt.savefig(f'feature_importance_{timestamp}.png', dpi=300, bbox_inches='tight')  # High-quality PNG
    plt.close()
    print("Feature importance plot saved successfully.")
except Exception as e:
    print(f"Error generating feature importance plot: {e}")

# Step 10: Save the Model
print("\nStep 10: Saving the Model")
joblib.dump(best_model, 'network_traffic_model.pkl')
print("Model saved as 'network_traffic_model.pkl'.")

# Step 11: Load the Model (Example)
# Uncomment the following lines to load and test the saved model
# loaded_model = joblib.load('network_traffic_model.pkl')
# y_pred_loaded = loaded_model.predict(X_test)
# print("Loaded Model Accuracy:", accuracy_score(y_test, y_pred_loaded))

print("\nScript completed successfully!")
