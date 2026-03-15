import tensorflow as tf
import mediapipe as mp
import cv2
import numpy as np

print(f"✅ TensorFlow can see GPU: {tf.config.list_physical_devices('GPU')}")
print(f"✅ Mediapipe version: {mp.__version__}")
print(f"✅ OpenCV version: {cv2.__version__}")
print(f"✅ NumPy version: {np.__version__}")