"""
LSTM Model Loader and Predictor for Fake News Detection
Handles loading and prediction using the trained LSTM model
"""

import os
import warnings
warnings.filterwarnings('ignore')

# Try to import TensorFlow and joblib
try:
    import tensorflow as tf
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    import joblib
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False


class LSTMFakeNewsModel:
    """LSTM Model for fake news detection"""
    
    def __init__(self, model_path=None, tokenizer_path=None):
        """
        Initialize the LSTM model
        
        Args:
            model_path: Path to saved model (.h5 file)
            tokenizer_path: Path to saved tokenizer (.joblib file)
        """
        self.model = None
        self.tokenizer = None
        self.max_len = 400  # Should match training max_len
        self.model_loaded = False
        
        # Default paths (can be overridden)
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'artifacts', 'lstm_fake_news_model.h5')
        if tokenizer_path is None:
            tokenizer_path = os.path.join(os.path.dirname(__file__), 'artifacts', 'tokenizer.joblib')
        
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path
        
        # Try to load model if TensorFlow is available
        if TENSORFLOW_AVAILABLE:
            self._load_model()
    
    def _load_model(self):
        """Load the saved model and tokenizer"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.tokenizer_path):
                print(f"Loading LSTM model from {self.model_path}")
                self.model = tf.keras.models.load_model(self.model_path)
                self.tokenizer = joblib.load(self.tokenizer_path)
                self.model_loaded = True
                print("LSTM model loaded successfully!")
            else:
                print(f"LSTM model files not found. Expected:")
                print(f"  Model: {self.model_path}")
                print(f"  Tokenizer: {self.tokenizer_path}")
                print("LSTM predictions will be disabled.")
        except Exception as e:
            print(f"Error loading LSTM model: {str(e)}")
            print("LSTM predictions will be disabled.")
            self.model_loaded = False
    
    def predict(self, text):
        """
        Predict if news is fake or real
        
        Args:
            text: Article text to analyze
            
        Returns:
            dict with:
                - prediction: "REAL" or "FAKE"
                - probability: float (0-1, where 1 = real, 0 = fake)
                - confidence: float (0-1)
                - available: bool (whether model is loaded)
        """
        if not TENSORFLOW_AVAILABLE:
            return {
                'prediction': None,
                'probability': None,
                'confidence': None,
                'available': False,
                'error': 'TensorFlow not installed'
            }
        
        if not self.model_loaded:
            return {
                'prediction': None,
                'probability': None,
                'confidence': None,
                'available': False,
                'error': 'Model not loaded'
            }
        
        try:
            # Preprocess text
            if not text or len(text.strip()) == 0:
                return {
                    'prediction': None,
                    'probability': None,
                    'confidence': None,
                    'available': True,
                    'error': 'Empty text provided'
                }
            
            # Tokenize and pad
            seq = self.tokenizer.texts_to_sequences([text])
            padded = pad_sequences(seq, maxlen=self.max_len, padding='post', truncating='post')
            
            # Predict
            proba = float(self.model.predict(padded, verbose=0)[0][0])
            
            # Determine prediction
            prediction = "REAL" if proba >= 0.5 else "FAKE"
            
            # Calculate confidence (distance from 0.5)
            confidence = abs(proba - 0.5) * 2  # 0 to 1 scale
            
            return {
                'prediction': prediction,
                'probability': round(proba, 4),
                'confidence': round(confidence, 4),
                'available': True,
                'error': None
            }
        except Exception as e:
            return {
                'prediction': None,
                'probability': None,
                'confidence': None,
                'available': True,
                'error': f'Prediction error: {str(e)}'
            }
    
    def is_available(self):
        """Check if model is loaded and ready"""
        return self.model_loaded and TENSORFLOW_AVAILABLE

