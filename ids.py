from pycaret.classification import load_model, predict_model
import streamlit as st
import pandas as pd
import numpy as np
import gzip, pickle, pickletools

#for decompressing
compressed_pkl = "ids_model_compressed.pkl"

with gzip.open(compressed_pkl, 'rb') as f:
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
			
    if add_selectbox == 'Online':
        duration = st.number_input('duration',  min_value=0, max_value=100000, value=0)
        protocol_type = st.selectbox('protocol_type', ['icmp', 'tcp','udp'])
        service = st.selectbox('service', ['ftp_data','other','private','http','remote_job','name','netbios_ns','eco_i','mtp','telnet','finger','domain_u','supdup','uucp_path','Z39_50','smtp','csnet_ns','uucp','netbios_dgm','urp_i','auth','domain','ftp','bgp','ldap','ecr_i','gopher','vmnet','systat','http_443','efs','whois','imap4','iso_tsap','echo','klogin','link','sunrpc','login','kshell','sql_net','time','hostnames','exec','ntp_u','discard','nntp','courier','ctf','ssh','daytime','shell','netstat','pop_3','nnsp','IRC','pop_2','printer','tim_i','pm_dump','red_i','netbios_ssn','rje','X11','urh_i','http_8001','aol','http_2784','tftp_u','harvest'])
        flag = st.selectbox('flag', ['REJ','SF','RSTO','S0','RSTR','SH','S3','S2','S1','RSTOS0','OTH'])
        src_bytes = st.number_input('src_bytes', value=0)
        dst_bytes = st.number_input('duration', value=0)
        land = st.selectbox('land', [0,1])
        wrong_fragment = st.number_input('wrong_fragment',  min_value=0, max_value=10, value=0)
        urgent = st.selectbox('urgent', [0,1,2,3])
	hot = st.number_input('wrong_fragment',  min_value=0, max_value=100000, value=0)
        num_failed_logins = st.number_input('num_failed_logins',  min_value=0, max_value=10, value=0)
        logged_in = st.selectbox('logged_in', [0,1])
        num_compromised = st.number_input('num_compromised',  min_value=0, max_value=100000, value=0)
        root_shell = st.selectbox('root_shell', [0,1])
        su_attempted = st.selectbox('su_attempted', [0,1])
        num_root = st.number_input('num_root',  min_value=0, max_value=100000, value=0)
        num_file_creations = st.number_input('num_file_creations',  min_value=0, max_value=100000, value=0)
        num_shells = st.number_input('num_shells',  min_value=0, max_value=10, value=0)
        num_access_files = st.number_input('num_access_files',  min_value=0, max_value=10, value=0)
        num_outbound_cmds = st.number_input('num_outbound_cmds',  min_value=0, max_value=100000, value=0)
        is_host_login = st.selectbox('is_host_login', [0,1])
        is_guest_login = st.selectbox('is_guest_login', [0,1])
        count = st.number_input('count',  min_value=0, max_value=100000, value=0)
        srv_count = st.number_input('srv_count',  min_value=0, max_value=100000, value=0)
        serror_rate = st.number_input('serror_rate',  min_value=0, max_value=100000, value=0)
        srv_serror_rate = st.number_input('srv_serror_rate',  min_value=0, max_value=100000, value=0)
        rerror_rate = st.number_input('rerror_rate',  min_value=0, max_value=100000, value=0)
        srv_rerror_rate = st.number_input('srv_rerror_rate',  min_value=0, max_value=100000, value=0)
        same_srv_rate = st.number_input('same_srv_rate',  min_value=0, max_value=100000, value=0)
        diff_srv_rate = st.number_input('diff_srv_rate',  min_value=0, max_value=100000, value=0)
        srv_diff_host_rate = st.number_input('srv_diff_host_rate',  min_value=0, max_value=100000, value=0)
        dst_host_count = st.number_input('dst_host_count',  min_value=0, max_value=100000, value=0)
        dst_host_srv_count = st.number_input('dst_host_srv_count',  min_value=0, max_value=100000, value=0)
        dst_host_same_srv_rate = st.number_input('dst_host_same_srv_rate',  min_value=0, max_value=100000, value=0)
        dst_host_diff_srv_rate = st.number_input('dst_host_diff_srv_rate',  min_value=0, max_value=100000, value=0)
        dst_host_same_src_port_rate = st.number_input('dst_host_same_src_port_rate',  min_value=0, max_value=100000, value=0)
        dst_host_srv_diff_host_rate = st.number_input('dst_host_srv_diff_host_rate',  min_value=0, max_value=100000, value=0)
        dst_host_serror_rate = st.number_input('dst_host_serror_rate',  min_value=0, max_value=100000, value=0)
        dst_host_srv_serror_rate = st.number_input('dst_host_srv_serror_rate',  min_value=0, max_value=100000, value=0)
        dst_host_rerror_rate = st.number_input('dst_host_rerror_rate',  min_value=0, max_value=100000, value=0)
        dst_host_srv_rerror_rate = st.number_input('dst_host_srv_rerror_rate',  min_value=0, max_value=100000, value=0)
        attack_type = st.selectbox('attack_type', ['neptune','warezclient','ipsweep','portsweep','teardrop','nmap','satan','smurf','pod','back','guess_passwd','ftp_write','multihop','rootkit','buffer_overflow','imap','warezmaster','phf','land','loadmodule','spy','perl'])
        difficulty_level = st.number_input('difficulty_level',  min_value=0, max_value=100000, value=0)
        output=""
        input_dict= {'duration':duration,
                        'protocol_type':protocol_type,
                        'service':service,
                        'flag':flag,
                        'src_bytes':src_bytes,
                        'dst_bytes':dst_bytes,
                        'land':land,
                        'wrong_fragment':wrong_fragment,
                        'urgent':urgent,
                        'hot':hot,
                        'num_failed_logins':num_failed_logins,
                        'logged_in':logged_in,
                        'num_compromised':num_compromised,
                        'root_shell':root_shell,
                        'su_attempted':su_attempted,
                        'num_root':num_root,
                        'num_file_creations':num_file_creations,
                        'num_shells':num_shells,
                        'num_access_files':num_access_files,
                        'num_outbound_cmds':num_outbound_cmds,
                        'is_host_login':is_host_login,
                        'is_guest_login':is_guest_login,
                        'count':count,
                        'srv_count':srv_count,
                        'serror_rate':serror_rate,
                        'srv_serror_rate':srv_serror_rate,
                        'rerror_rate':rerror_rate,
                        'srv_rerror_rate':srv_rerror_rate,
                        'same_srv_rate':same_srv_rate,
                        'diff_srv_rate':diff_srv_rate,
                        'srv_diff_host_rate':srv_diff_host_rate,
                        'dst_host_count':dst_host_count,
                        'dst_host_srv_count':dst_host_srv_count,
                        'dst_host_same_srv_rate':dst_host_same_srv_rate,
                        'dst_host_diff_srv_rate':dst_host_diff_srv_rate,
                        'dst_host_same_src_port_rate':dst_host_same_src_port_rate,
                        'dst_host_srv_diff_host_rate':dst_host_srv_diff_host_rate,
                        'dst_host_serror_rate':dst_host_serror_rate,
                        'dst_host_srv_serror_rate':dst_host_srv_serror_rate,
                        'dst_host_rerror_rate':dst_host_rerror_rate,
                        'dst_host_srv_rerror_rate':dst_host_srv_rerror_rate,
                        'attack_type':attack_type,
                        'difficulty_level':difficulty_level}
        input_df = pd.DataFrame([input_dict])
        if st.button("Predict"):
            output = predict(model=model, input_df=input_df)
            output = str(output)
        st.success('The output is {}'.format(output))		
def main():
    run()

if __name__ == "__main__":
  main()
