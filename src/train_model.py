import pandas as pd
import joblib
import os
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

def train_bert_classifier(data_path=None, output_path=None):
    """Train BERT classifier for log classification
    
    Args:
        data_path (str): Path to the synthetic logs CSV file
        output_path (str): Path to save the trained model
    """
    # Get the directory of the current script (src)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set default paths relative to the script's location
    if data_path is None:
        # Navigate from src to data directory (one level up, then into data)
        data_path = os.path.join(script_dir, "..", "data", "synthetic_logs.csv")
    if output_path is None:
        # Navigate from src to models directory (one level up, then into models)
        output_path = os.path.join(script_dir, "..", "models", "log_classifier.joblib")
    
    # Normalize paths to resolve any '..' references
    data_path = os.path.normpath(data_path)
    output_path = os.path.normpath(output_path)
    
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    
    # Check if data file exists
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found at: {data_path}")
    
    # Load data
    print(f"Loading data from: {data_path}")
    df = pd.read_csv(data_path)
    
    # Check if required columns exist
    required_columns = ['log_message', 'target_label']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns in CSV: {missing_columns}")
    
    # Use 'log_message' for features and 'target_label' for labels
    X = df['log_message'].values
    y = df['target_label'].values
    
    # Load BERT model for sentence embeddings
    print("Loading SentenceTransformer model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Generate embeddings
    print("Generating BERT embeddings...")
    X_embeddings = model.encode(X, show_progress_bar=True)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_embeddings, y, test_size=0.2, random_state=42
    )
    
    # Train classifier
    print("Training Logistic Regression classifier...")
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)
    
    # Evaluate model
    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model
    print(f"Saving model to: {output_path}")
    joblib.dump(clf, output_path)
    
    return clf

if __name__ == "__main__":
    # Train the model with default paths
    train_bert_classifier()