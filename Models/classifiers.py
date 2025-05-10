import json
from os import path
from sklearn.model_selection import StratifiedKFold, train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, make_scorer
import csv, sys, numpy as np, seaborn as sns, matplotlib.pyplot as plt
from sklearn.calibration import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from Dataset.dataset import Dataset
from Models.kmeans import kMeans
from preprocessor import *

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

class ModelTrainerClass:
    def __init__(self, filepath, target_column, drop_columns,additional_features=None):
        self.filepath = filepath
        self.target_column = target_column
        self.drop_columns = drop_columns
        self.additional_features = additional_features
        self.X, self.y = self.load_and_preprocess_data(additional_features=additional_features)

    def load_and_preprocess_data(self, additional_features=None):
        dataset = Dataset(self.filepath)
        dataset = datasetPreprocessor(dataset)

        features = dataset.getDataFrame(['Source Port', 'Destination Port', 'Packet Length'])
        kmeans = kMeans().clustering(features, "Network")
        dataset.addDatasetColumn('Network Features Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=['Source Port', 'Destination Port', 'Packet Length'])
        dataset.normalizeColumn('Network Features Cluster')

        base_features = ['OS_Linux', 'OS_Mac OS', 'OS_Windows', 'OS_iPad OS', 'OS_iPhone OS', 'Browser_Firefox', 'Browser_MSIE', 'Browser_Opera', 'Browser_Safari']
        
        if additional_features:
            base_features.extend(additional_features)

        features = dataset.getDataFrame(base_features)
        kmeans = kMeans().clustering(features, "UserAgent")
        dataset.addDatasetColumn('UserAgent Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=base_features)
        dataset.normalizeColumn('UserAgent Cluster')

        vulnerabilities = dataset.getColumn(self.target_column)
        values = np.array(vulnerabilities)
        label_encoder = LabelEncoder()
        integer_encoded = label_encoder.fit_transform(values)
        onehot_encoder = OneHotEncoder(sparse_output=False)
        integer_encoded = integer_encoded.reshape(len(integer_encoded), 1)
        y = onehot_encoder.fit_transform(integer_encoded)
        dataset.dropDatasetColumns(self.drop_columns)
        X = dataset.getDataset()

        return X, y

    def evaluate_model(self, model, X_test, y_test, name):
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision_micro = precision_score(y_test, y_pred, average='micro')
        recall_micro = recall_score(y_test, y_pred, average='micro')
        f1_micro = f1_score(y_test, y_pred, average='micro')
        f1_macro = f1_score(y_test, y_pred, average='macro')
        print('Accuracy:', accuracy)
        print('Precision (micro):', precision_micro)
        print('Recall (micro):', recall_micro)
        print('F1_micro score:', f1_micro)
        print('F1_macro score:', f1_macro)

        with open('Evaluation/metrics_' + name + '.csv', 'w', newline='') as csvfile:
            fieldnames = ['Metric', 'Value']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerow({'Metric': 'Accuracy', 'Value': accuracy})
            writer.writerow({'Metric': 'Precision (micro)', 'Value': precision_micro})
            writer.writerow({'Metric': 'Recall (micro)', 'Value': recall_micro})
            writer.writerow({'Metric': 'F1_micro score', 'Value': f1_micro})
            writer.writerow({'Metric': 'F1_macro score', 'Value': f1_macro})

        plt.close('all')
        y_pred_decoded = np.argmax(y_pred, axis=1)
        y_test_decoded = np.argmax(y_test, axis=1)
        cm = confusion_matrix(y_test_decoded, y_pred_decoded)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        class_labels = ['1:TCP', '2: UDP', '3: ICMP']
        plt.yticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xlabel('Predicted Class')
        plt.ylabel('True Class')
        plt.title('Confusion Matrix')
        plt.savefig('Evaluation/Confusion_Matrix_' + name + '.png', bbox_inches='tight')

    def cross_validate_model(self, model, X, y):
        cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        print('Cross-validation scores:', cv_scores)
        print('Mean cross-validation score:', np.mean(cv_scores))

    def save_best_params(self, best_params, name):
        with open('Evaluation/best_params_' + name + '.json', 'w') as file:
            json.dump(best_params, file)

    def load_best_params(self, name):
        filepath = 'Evaluation/best_params_' + name + '.json'
        if path.exists(filepath):
            with open(filepath, 'r') as file:
                return json.load(file)
        return None

    def train_and_evaluate_with_hyperparams(self, model, param_grid, name):
        best_params = self.load_best_params(name)
        if best_params:
            print(f'Using saved best parameters for {name}:', best_params)
            model.set_params(**best_params)
            X_train, X_test, y_train, y_test = train_test_split(self.X, self.y, test_size=0.2, random_state=42)
            model.fit(X_train, y_train)
            self.evaluate_model(model, X_test, y_test, name)
            return model

        scorer = make_scorer(accuracy_score)
        cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
        grid_search = GridSearchCV(model, param_grid, scoring=scorer, cv=cv, verbose=1)
        grid_search.fit(self.X, self.y)

        print(f'Best parameters for {name}:', grid_search.best_params_)
        print(f'Best cross-validation score for {name}:', grid_search.best_score_)

        self.save_best_params(grid_search.best_params_, name)

        best_model = grid_search.best_estimator_

        # Evaluate on test set
        X_train, X_test, y_train, y_test = train_test_split(self.X, self.y, test_size=0.2, random_state=42)
        best_model.fit(X_train, y_train)
        self.evaluate_model(best_model, X_test, y_test, name)

        return best_model
    
    def train_model_DecisionTreeClassifier(self, name):
        model = DecisionTreeClassifier(random_state=42)
        param_grid = {
            'max_depth': [None, 10, 20, 30],
            'criterion': ['gini', 'entropy'],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        self.train_and_evaluate_with_hyperparams(model, param_grid, name)

    def train_model_RandomForestClassifier(self, name):
        model = RandomForestClassifier(random_state=42)
        param_grid = {
            'n_estimators': [50, 100],
            'criterion': ['gini', 'entropy'],
            'max_depth': [None, 10, 20],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        self.train_and_evaluate_with_hyperparams(model, param_grid, name)

    def train_model_KNN(self, name):
        model = KNeighborsClassifier()
        param_grid = {
            'n_neighbors': [3, 5, 7]
        }
        self.train_and_evaluate_with_hyperparams(model, param_grid, name)

    def run(self):
        models = {
            'DecisionTreeClassifier': self.train_model_DecisionTreeClassifier,
            'RandomForestClassifier': self.train_model_RandomForestClassifier,
        }

        for model_name, model_function in models.items():
            model_function(model_name)