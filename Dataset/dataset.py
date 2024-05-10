import pandas
import warnings
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, LabelEncoder
warnings.filterwarnings("ignore", category=FutureWarning) #va rimosso prima o poi

class Dataset:
    def __init__(self, path):
        self.dataset = pandas.read_csv(path)
        
    def getDataset(self):
        return self.dataset
    
    def setDataset(self, dataset):
        self.dataset = dataset

    def dropDatasetColumns(self, columnsToRemove):
        self.dataset = self.dataset.drop(columns = columnsToRemove)

    def saveDataset(self, path):
        self.dataset.to_csv(path, index = False)
        
    def getColumn(self, column):
        return self.dataset[column]
    
    def normalizeColumn(self, column):
        scalera = MinMaxScaler()
        self.dataset[column] = scalera.fit_transform(self.dataset[[column]])
        
    def emptyValues(self, column, toReplace):
        self.dataset[column] = self.dataset[column].replace(toReplace, 1).fillna(0)

    def getDummies(self, column):
        self.dataset = pandas.get_dummies(self.dataset, columns=[column], drop_first=True)
        
    def replaceBoolean(self):
        self.dataset = self.dataset.replace({True:1, False:0})
        
    def EDA(self):
        #uniqueness analysis
        uniqueValues = self.dataset.nunique()
        length = len(self.dataset)
        uniqueValues = uniqueValues/length
        uniqueValues.to_csv("EDA/unique_values.csv")
        
        #null Values 
        missingValues = self.dataset.isnull().sum()
        missingValues.to_csv("EDA/missing_values.csv")