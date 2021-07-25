from pycaret.classification import load_model, predict_model
import streamlit as st
import pandas as pd
import numpy as np
import gzip, pickle, pickletools

#for decompressing
compressed_pkl = "ids_model_compressed.pkl"

with gzip.open(filepath, 'rb') as f:
    p = pickle.Unpickler(f)
    model = p.load()       

def predict(model, input_df):
    predictions_df = predict_model(estimator=model, data=input_df)
    predictions = predictions_df['Label'][0]
    return predictions

def run():
    from PIL import Image
    baner_img = Image.open('ids.png')
    safe_img = Image.open('safe.jpg')
    attack_img = Image.open('intrusion.jpg')


    st.image(baner_img,use_column_width=True)
    add_selectbox = st.sidebar.selectbox(
    "How would you like to predict?",
    ("Online", "Batch"))

    st.sidebar.info('This app is created to analyse data packets and determine whether it is an attack or not ')
    st.sidebar.success('https://www.pycaret.org')
    st.sidebar.image(baner_img)
    st.title("Predicting attack")

    if add_selectbox == 'Batch':
        file_upload = st.file_uploader("Upload csv file for predictions", type=["csv"])
        if file_upload is not None:
            data = pd.read_csv(file_upload)            
            predictions = predict_model(estimator=model,data=data)
            st.write(predictions)
def main():
    run()

if __name__ == "__main__":
  main()
