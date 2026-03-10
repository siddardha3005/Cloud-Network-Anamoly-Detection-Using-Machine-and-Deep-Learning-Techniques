from django.db.models import Count
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404

import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score
# Create your views here.
from Remote_User.models import ClientRegister_Model,Network_Anomaly,detection_ratio,detection_accuracy

def login(request):


    if request.method == "POST" and 'submit1' in request.POST:

        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            enter = ClientRegister_Model.objects.get(username=username,password=password)
            request.session["userid"] = enter.id

            return redirect('ViewYourProfile')
        except:
            pass

    return render(request,'RUser/login.html')

def index(request):
    return render(request, 'RUser/index.html')

def Add_DataSet_Details(request):

    return render(request, 'RUser/Add_DataSet_Details.html', {"excel_data": ''})


def Register1(request):

    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        phoneno = request.POST.get('phoneno')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        address = request.POST.get('address')
        gender = request.POST.get('gender')
        ClientRegister_Model.objects.create(username=username, email=email, password=password, phoneno=phoneno,
                                            country=country, state=state, city=city,address=address,gender=gender)

        obj = "Registered Successfully"
        return render(request, 'RUser/Register1.html',{'object':obj})
    else:
        return render(request,'RUser/Register1.html')

def ViewYourProfile(request):
    userid = request.session['userid']
    obj = ClientRegister_Model.objects.get(id= userid)
    return render(request,'RUser/ViewYourProfile.html',{'object':obj})


def Predict_Network_Anomaly(request):
    if request.method == "POST":

        if request.method == "POST":

            Login_Frequency= request.POST.get('Login_Frequency')
            Failed_Login_Attempts= request.POST.get('Failed_Login_Attempts')
            Data_Transferred_MB= request.POST.get('Data_Transferred_MB')
            Session_Duration_Minutes= request.POST.get('Session_Duration_Minutes')
            Accessed_Files= request.POST.get('Accessed_Files')
            Password_Changes= request.POST.get('Password_Changes')
            IP_Location_Changes= request.POST.get('IP_Location_Changes')
            Malware_Detections= request.POST.get('Malware_Detections')
            Suspicious_URL_Clicks= request.POST.get('Suspicious_URL_Clicks')
            Time_Since_Last_Login_Hours= request.POST.get('Time_Since_Last_Login_Hours')
            

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
        print("ACCURACY")
        print(svm_acc)
        print("CLASSIFICATION REPORT")
        print(classification_report(y_test, predict_svm))
        print("CONFUSION MATRIX")
        print(confusion_matrix(y_test, predict_svm))
        models.append(('svm', lin_clf))

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

        print("Gradient Boosting Classifier")
        gb_model = GradientBoostingClassifier()
        gb_model.fit(X_train, y_train)
        dtcpredict = gb_model.predict(X_test)
        print("ACCURACY")
        print(accuracy_score(y_test, dtcpredict) * 100)
        print("CLASSIFICATION REPORT")
        print(classification_report(y_test, dtcpredict))
        print("CONFUSION MATRIX")
        print(confusion_matrix(y_test, dtcpredict))
        models.append(('GradientBoostingClassifier', gb_model))

        classifier = VotingClassifier(models)
        classifier.fit(X_train, y_train)
        y_pred = classifier.predict(X_test)

        # Input for prediction
        input_data = [[Login_Frequency, Failed_Login_Attempts, Data_Transferred_MB, Session_Duration_Minutes, Accessed_Files, Password_Changes, IP_Location_Changes, Malware_Detections, Suspicious_URL_Clicks, Time_Since_Last_Login_Hours]]
        predicted_class_index = classifier.predict(input_data)[0]
        predicted_class = label_encoder.inverse_transform([predicted_class_index])[0]
        Network_Anomaly.objects.create(
        Login_Frequency=Login_Frequency,
        Failed_Login_Attempts=Failed_Login_Attempts,
        Data_Transferred_MB=Data_Transferred_MB,
        Session_Duration_Minutes=Session_Duration_Minutes,
        Accessed_Files=Accessed_Files,
        Password_Changes=Password_Changes,
        IP_Location_Changes=IP_Location_Changes,
        Malware_Detections=Malware_Detections,
        Suspicious_URL_Clicks=Suspicious_URL_Clicks,
        Time_Since_Last_Login_Hours=Time_Since_Last_Login_Hours,        
        Prediction=predicted_class)

        return render(request, 'RUser/Predict_Network_Anomaly.html',{'objs': predicted_class})
    return render(request, 'RUser/Predict_Network_Anomaly.html')



