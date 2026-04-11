import tf2onnx
import tensorflow as tf
import onnxruntime as rt
import numpy as np
import os
from loguru import logger

MODEL_IN   = r"D:\project\nesrd\nesrd\core\models\ransomware_detector_ransap_v3.h5"
MODEL_KERAS = r"D:\project\nesrd\nesrd\core\models\ransomware_detector_v3.keras"
MODEL_OUT  = r"D:\project\nesrd\nesrd\core\models\ransomware_detector_v3.onnx"

def main():
    logger.info("Loading Keras model...")
    model = tf.keras.models.load_model(MODEL_IN)

    # Save in new Keras format first
    logger.info("Saving in new Keras format...")
    model.save(MODEL_KERAS)

    # Reload from new format
    logger.info("Reloading model...")
    model = tf.keras.models.load_model(MODEL_KERAS)

    logger.info("Converting to ONNX...")
    input_signature = [
        tf.TensorSpec(shape=(None, 50, 50), dtype=tf.float32, name="input")
    ]

    model_proto, _ = tf2onnx.convert.from_keras(
        model,
        input_signature=input_signature,
        output_path=MODEL_OUT,
        opset=13
    )

    logger.info(f"ONNX model saved to: {MODEL_OUT}")

    # Benchmark
    logger.info("\nBenchmarking...")
    test_input = np.random.randn(1, 50, 50).astype(np.float32)
    runs = 100

    # Keras speed
    import time
    start = time.time()
    for _ in range(runs):
        model.predict(test_input, verbose=0)
    keras_time = (time.time() - start) / runs * 1000

    # ONNX speed
    sess = rt.InferenceSession(MODEL_OUT)
    input_name = sess.get_inputs()[0].name
    start = time.time()
    for _ in range(runs):
        sess.run(None, {input_name: test_input})
    onnx_time = (time.time() - start) / runs * 1000

    logger.info(f"Keras inference: {keras_time:.2f}ms per call")
    logger.info(f"ONNX inference:  {onnx_time:.2f}ms per call")
    logger.info(f"Speedup: {keras_time/onnx_time:.1f}x faster")

if __name__ == "__main__":
    main()