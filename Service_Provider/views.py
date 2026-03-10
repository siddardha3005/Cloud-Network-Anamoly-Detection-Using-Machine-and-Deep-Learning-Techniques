
from django.db.models import  Count, Avg
from django.shortcuts import render, redirect
from django.db.models import Count
from django.db.models import Q
import datetime
import xlwt
from django.http import HttpResponse


import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
 
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier, VotingClassifier
 
# Create your views here.
from Remote_User.models import ClientRegister_Model,Network_Anomaly,detection_ratio,detection_accuracy


def serviceproviderlogin(request):
    if request.method  == "POST":
        admin = request.POST.get('username')
        password = request.POST.get('password')
        if admin == "Admin" and password =="Admin":
            detection_accuracy.objects.all().delete()
            return redirect('View_Remote_Users')

    return render(request,'SProvider/serviceproviderlogin.html')

def View_Predicted_Network_Anomaly_Type_Ratio(request):
    detection_ratio.objects.all().delete()
    ratio = ""
    kword = 'Phishing'
    print(kword)
    obj = Network_Anomaly.objects.all().filter(Q(Prediction=kword))
    obj1 = Network_Anomaly.objects.all()
    count = obj.count();
    count1 = obj1.count();
    ratio = (count / count1) * 100
    if ratio != 0:
        detection_ratio.objects.create(names=kword, ratio=ratio)

    ratio12 = ""
    kword12 = 'Malware'
    print(kword12)
    obj12 = Network_Anomaly.objects.all().filter(Q(Prediction=kword12))
    obj112 = Network_Anomaly.objects.all()
    count12 = obj12.count();
    count112 = obj112.count();
    ratio12 = (count12 / count112) * 100
    if ratio12 != 0:
        detection_ratio.objects.create(names=kword12, ratio=ratio12)

    ratio13 = ""
    kword13 = 'Brute_Force'
    print(kword13)
    obj13 = Network_Anomaly.objects.all().filter(Q(Prediction=kword13))
    obj113 = Network_Anomaly.objects.all()
    count13 = obj13.count();
    count113 = obj113.count();
    ratio13 = (count13 / count113) * 100
    if ratio13 != 0:
        detection_ratio.objects.create(names=kword13, ratio=ratio13)


    obj = detection_ratio.objects.all()
    return render(request, 'SProvider/View_Predicted_Network_Anomaly_Type_Ratio.html', {'objs': obj})

def View_Remote_Users(request):
    obj=ClientRegister_Model.objects.all()
    return render(request,'SProvider/View_Remote_Users.html',{'objects':obj})

def charts(request,chart_type):
    chart1 = detection_ratio.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts.html", {'form':chart1, 'chart_type':chart_type})

def charts1(request,chart_type):
    chart1 = detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts1.html", {'form':chart1, 'chart_type':chart_type})

def View_Predicted_Network_Anomaly_Type(request):
    obj =Network_Anomaly.objects.all()
    return render(request, 'SProvider/View_Predicted_Network_Anomaly_Type.html', {'list_objects': obj})

def likeschart(request,like_chart):
    charts =detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/likeschart.html", {'form':charts, 'like_chart':like_chart})


def Download_Predicted_DataSets(request):

    response = HttpResponse(content_type='application/ms-excel')
    # decide file name
    response['Content-Disposition'] = 'attachment; filename="Predicted_Datasets.xls"'
    # creating workbook
    wb = xlwt.Workbook(encoding='utf-8')
    # adding sheet
    ws = wb.add_sheet("sheet1")
    # Sheet header, first row
    row_num = 0
    font_style = xlwt.XFStyle()
    # headers are bold
    font_style.font.bold = True
    # writer = csv.writer(response)
    obj = Network_Anomaly.objects.all()
    data = obj  # dummy method to fetch data.
    for my_row in data:
        row_num = row_num + 1

        ws.write(row_num, 0, my_row.Login_Frequency, font_style)
        ws.write(row_num, 1, my_row.Failed_Login_Attempts, font_style)
        ws.write(row_num, 2, my_row.Failed_Login_Attempts, font_style)
        ws.write(row_num, 3, my_row.Session_Duration_Minutes, font_style)
        ws.write(row_num, 4, my_row.Accessed_Files, font_style)
        ws.write(row_num, 5, my_row.Password_Changes, font_style)
        ws.write(row_num, 6, my_row.IP_Location_Changes, font_style)
        ws.write(row_num, 7, my_row.Malware_Detections, font_style)
        ws.write(row_num, 8, my_row.Suspicious_URL_Clicks, font_style)
        ws.write(row_num, 9, my_row.Time_Since_Last_Login_Hours, font_style)        
        ws.write(row_num, 10, my_row.Prediction, font_style)


    wb.save(response)
    return response

def train_model(request):
    detection_accuracy.objects.all().delete()

    models = []
    dataset = pd.read_csv('Network_Anomaly_data.csv')
        # Preprocessing
    X = dataset.drop('Attack_Type', axis=1)
    y = dataset['Attack_Type']

        # Encode the target variable (Attack_Type) as it is categorical
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

        # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)



    # SVM Model
    print("SVM")
    from sklearn import svm
    lin_clf = svm.LinearSVC()
    lin_clf.fit(X_train, y_train)
    predict_svm = lin_clf.predict(X_test)
    svm_acc = accuracy_score(y_test, predict_svm) * 100
    print(svm_acc)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, predict_svm))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, predict_svm))
    models.append(('svm', lin_clf))
    detection_accuracy.objects.create(names="SVM", ratio=svm_acc)

    print("Logistic Regression")

    from sklearn.linear_model import LogisticRegression
    reg = LogisticRegression(random_state=0, solver='lbfgs').fit(X_train, y_train)
    y_pred = reg.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, y_pred) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred))
    models.append(('logistic', reg))
    detection_accuracy.objects.create(names="Logistic Regression", ratio=accuracy_score(y_test, y_pred) * 100)

    print("GradientBoostingClassifier")
    dtc = GradientBoostingClassifier()
    dtc.fit(X_train, y_train)
    dtcpredict = dtc.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, dtcpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, dtcpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, dtcpredict))
    models.append(('GradientBoostingClassifier', dtc))
    detection_accuracy.objects.create(names="Gradient Boosting Classifier", ratio=accuracy_score(y_test, dtcpredict) * 100)

    print("VotingClassifier")

  
    classifier = VotingClassifier(models)
    classifier.fit(X_train, y_train)
    knpredict = classifier.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, knpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, knpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, knpredict))
    detection_accuracy.objects.create(names="VotingClassifier", ratio=accuracy_score(y_test, knpredict) * 100)



    csv_format = 'Results.csv'
    dataset.to_csv(csv_format, index=False)
    dataset.to_markdown

    obj = detection_accuracy.objects.all()
    return render(request,'SProvider/train_model.html', {'objs': obj})