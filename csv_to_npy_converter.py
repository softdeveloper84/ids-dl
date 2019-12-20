import os
import time
import csv
import numpy as np

PATH_TO_INPUT_FOLDER = "../data/csv/MachineLearningCVE"
PATH_TO_OUTPUT_FOLDER = "../data/out"


def print_column_names():
    names = "Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, " \
            "Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, " \
            "Fwd Packet Length Std,Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, " \
            "Bwd Packet Length Std,Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, " \
            "Flow IAT Min,Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,Bwd IAT Total, " \
            "Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, " \
            "Bwd URG Flags, Fwd Header Length, Bwd Header Length,Fwd Packets/s, Bwd Packets/s, Min Packet Length, " \
            "Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,FIN Flag Count, " \
            "SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, " \
            "ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, " \
            "Fwd Header Length,Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, " \
            "Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, " \
            "Subflow Bwd Bytes,Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, " \
            "min_seg_size_forward,Active Mean, Active Std, Active Max, Active Min,Idle Mean, Idle Std, " \
            "Idle Max, Idle Min, Label"
    for i, name in enumerate(names.split(",")):
        print(i, name.strip())


if __name__ == "__main__":
    counter = 0
    actual = (50 ** 2) * 3
    start_time = time.time()
    for file in os.listdir(PATH_TO_INPUT_FOLDER):
        data_array = np.empty((0, 2))
        with open(os.path.join(PATH_TO_INPUT_FOLDER, file)) as csv_file:
            print(file)
            csv_rows = csv.reader(csv_file, delimiter=",", quotechar='|')
            for i, row in enumerate(csv_rows):
                if i == 0:
                    continue
                if counter % 1000 == 0:
                    print(counter)
                value_0 = row[0]
                if len(value_0) > actual:
                    value_0 = value_0[:actual]
                if row[-1] == 'BENIGN':
                    data_array = np.vstack((data_array, np.array([np.fromstring(value_0, dtype=np.uint8), 0])))
                else:
                    data_array = np.vstack((data_array, np.array([np.fromstring(value_0, dtype=np.uint8), 1])))
                counter += 1
        print('Time taken: {} sec.'.format(time.time() - start_time), file)
        print('counter: ', counter)
        np.save(os.path.join(PATH_TO_OUTPUT_FOLDER, 'destinationPayload_' + file), np.array(data_array))
