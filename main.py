#!/usr/bin/env python
# coding: utf-8
# Developed YES


import os
import csv
import pefile
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import KFold, cross_validate
import pickle
import convert_feature

def get_pe_feature():

    # file_path = 'E:/datasecurity/train_data/'
    # file_path = 'E:/datasecurity/sample_data/'
    file_path = 'E:/datasecurity/test_data/'
    files = os.listdir(file_path)

    Real_COLS = [
            'filename', 'e_magic', 'e_ifanew', 'Signature', 'Machine', 'NumberOfSections',
            'TimeDateStamp', 'SizeOfOptionalHeader', 'Characteristics', 'Magic', 'AddressOfEntryPoint', 'ImageBase', "SectionAlignment", "FileAlignment",
            'SizeOfImage', 'Subsystem', 'SectionFlag', 'IsPacker', 'Richheader', 'Richheader_checksum', '.textSectionVirtualSize', '.textSectionSizeOfRawData', '.textSectionPointerToRawData',
            '.textSectionCharacteristics', '.dataSectionVirtualSize', '.dataSectionSizeOfRawData', '.dataSectionPointerToRawData',
            '.dataSectionCharacteristics', '.rsrcSectionVirtualSize', '.rsrcSectionSizeOfRawData', '.rsrcSectionPointerToRawData',
            '.rsrcSectionCharacteristics', '.rdataSectionVirtualSize', '.rdataSectionSizeOfRawData', '.rdataSectionPointerToRawData',
            '.rdataSectionCharacteristics', '.relocSectionVirtualSize', '.relocSectionSizeOfRawData', '.relocSectionPointerToRawData',
            '.relocSectionCharacteristics'
        ]

    NULL_ROW = [0 for x in Real_COLS]

    with open('./pe_features_test.csv', 'w', newline='') as fp:
    # with open('./pe_features_train.csv', 'w', newline='') as fp:
    # with open('./pe_features_validation.csv', 'w', newline='') as fp:
        wp = csv.writer(fp)
        wp.writerow(Real_COLS)

        filepath = file_path #'./sample_data'
        files = os.listdir(filepath)

        for idx, filename in enumerate(files):
            fullname = os.path.join(filepath, filename)
            with open(fullname, 'rb') as f:
                pe_stream = f.read()
                try:
                    pe = pefile.PE(fullname)
                    feature = convert_feature.extract_pe_features(pe, file_path, filename, pe_stream)
                except:
                    print('[+] {}'.format(filename))
                    feature = NULL_ROW
                    feature[0] = filename
            wp.writerow(feature)
            print(feature)

def main():

    validation_data = pd.read_csv('./pe_features_validation.csv')
    train_data = pd.read_csv('./pe_features_train.csv')
    test_data = pd.read_csv('./pe_features_test.csv')

    for col in validation_data.columns:
        if 'None' in validation_data[col].tolist() or 'Error' in validation_data[col].tolist():
            validation_data = validation_data.drop(columns=col, axis=0)

    for col in train_data.columns:
        if 'None' in train_data[col].tolist() or 'Error' in train_data[col].tolist():
            train_data = train_data.drop(columns=col, axis=0)

    for col in test_data.columns:
        if 'None' in test_data[col].tolist() or 'Error' in train_data[col].tolist():
            test_data = test_data.drop(columns=col, axis=0)

    validation_data.to_csv('./pe_features_sample.csv', index=False)
    train_data.to_csv('./pe_features_train.csv', index=False)
    test_data.to_csv('./pe_features_test.csv', index=False)

    validation_label = pd.read_csv('./validation_label.csv')
    train_label = pd.read_csv('./train_label.csv')
    test_label = pd.read_csv('./test_label.csv')

    validation_data = validation_data.join(validation_label.set_index('filename')['label'], on='filename')
    validation_label = validation_data['label']
    validation_data = validation_data.drop(columns=['filename', 'label'], axis=1)

    train_data = train_data.join(train_label.set_index('filename')['label'], on='filename')
    train_label = train_data['label']
    train_data = train_data.drop(columns=['filename', 'label'], axis=1)

    # test_data = test_data.join(test_label.set_index('filename')['label'], on='filename')
    test_name = test_data['filename']
    test_data = test_data.drop(columns=['filename'], axis=1)

    # Missing Value Prediction
    imputer = SimpleImputer(strategy='median')
    imputer.fit(train_data)
    train_data = imputer.transform(train_data)

    # Normalization using StandardScaler or RobustScaler
    # 결과값이 좋지않아 사용하지 않음
    # stand_scaler = StandardScaler()
    # stand_scaler.fit(train_data)
    # train_data = stand_scaler.transform(train_data)

    tr_x, va_x, tr_y, va_y = train_test_split(train_data, train_label, test_size=0.2, random_state=10)
    # tr_X, te_X, tr_y, te_y = train_test_split(validation_data, validation_targets, test_size=0.2, random_state=10)
    model = xgb.XGBClassifier(n_estimators=1000, learning_rate=0.2, colsample_bytree=1, max_depth=8, tree_method='gpu_hist')
    model.fit(train_data, train_label)

    with open('./pe_model.pickle', 'wb') as f:
        pickle.dump(model, f)

    pred_y = model.predict(test_data)
    score = model.predict_proba(test_data)[:, 1]

    with open('./test_label_value.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['filename', 'label'])
        for fn, pred in zip(list(test_name), list(pred_y)):
            w.writerow([fn, pred])


    # report = classification_report(validation_label, pred_y)
    # auc = roc_auc_score(validation_label, score)

    # folding = KFold(n_splits=7, shuffle=True, random_state=10)
    # scores = cross_validate(model, train_data, train_label, cv=folding, scoring=["precision_macro", "roc_auc", "f1"])
    #
    # # print(scores, type[scores])
    # print('[*] precision: ', scores['test_precision_macro'].mean())
    # print('[*] Roc-AUC: ', scores['test_roc_auc'].mean())
    # print('[*] f1: ', scores['test_f1'].mean())
    # print(report)
    # print('================================')
    # print(auc)

if __name__ == '__main__':
    # get_pe_feature()
    main()


