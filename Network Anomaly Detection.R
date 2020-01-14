################################
# Create edx set, validation set
################################

if(!require(tidyverse)) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
if(!require(caret)) install.packages("caret", repos = "http://cran.us.r-project.org")
if(!require(data.table)) install.packages("data.table", repos = "http://cran.us.r-project.org")
if(!require(corrplot)) install.packages("corrplot", repos = "http://cran.us.r-project.org")
if(!require(gam)) install.packages("gam", repos = "http://cran.us.r-project.org")
if(!require(dplyr)) install.packages("dplyr", repos = "http://cran.us.r-project.org")
if(!require(Gifi)) install.packages("Gifi", repos = "http://cran.us.r-project.org")
if(!require(PCAmix)) install.packages("PCAmix", repos = "http://cran.us.r-project.org")
if(!require(FactoMineR)) install.packages("FactoMineR", repos = "http://cran.us.r-project.org")
if(!require(readr)) install.packages("readr", repos = "http://cran.us.r-project.org")
if(!require(DataExplorer)) install.packages("DataExplorer", repos = "http://cran.us.r-project.org")
if(!require(ggplot2)) install.packages("ggplot2", repos = "http://cran.us.r-project.org")
if(!require(factoextra)) install.packages("factoextra", repos = "http://cran.us.r-project.org")
if(!require(tidyr)) install.packages("tidyr", repos = "http://cran.us.r-project.org")
if(!require(ranger)) install.packages("ranger", repos = "http://cran.us.r-project.org")


options(digits=3, scipen=999)
dl <- tempfile()
#Downloading the files
download.file("https://raw.githubusercontent.com/charlessuresh/Network-Anomaly-Detection-Classification/master/network-anamoly-detection.zip", dl,mode="wb")


unzip(dl, files = c("Train.txt","Test.txt"))
set_1 <- read_delim("Train.txt", delim=",",col_names = c("duration","protocol_type",
                                                         "service","flag","src_bytes",
                                                         "dst_bytes","land", "wrong_fragment",
                                                         "urgent","hot","num_failed_logins",
                                                         "logged_in", "num_compromised",
                                                         "root_shell","su_attempted","num_root",
                                                         "num_file_creations","num_shells",
                                                         "num_access_files","num_outbound_cmds",
                                                         "is_hot_login", "is_guest_login","count",
                                                         "srv_count","serror_rate", "srv_serror_rate",
                                                         "rerror_rate","srv_rerror_rate","same_srv_rate",
                                                         "diff_srv_rate", "srv_diff_host_rate",
                                                         "dst_host_count","dst_host_srv_count",
                                                         "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                                                         "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                                                         "dst_host_serror_rate","dst_host_srv_serror_rate",
                                                         "dst_host_rerror_rate","dst_host_srv_rerror_rate",
                                                         "attack", "last_flag"),
                    col_types = list(col_double(),col_factor(),col_factor(),col_factor(),col_integer(),col_integer(),
                                     col_factor(),col_integer(),col_integer(),col_integer(),col_integer(),
                                     col_factor(),col_integer(),col_factor(),col_integer(),col_integer(),
                                     col_integer(),col_integer(),col_integer(),col_integer(),col_factor(),
                                     col_factor(),col_integer(),col_integer(),col_double(),col_double(),
                                     col_double(),col_double(),col_double(),col_double(),col_double(),
                                     col_integer(),col_integer(),col_double(),col_double(),col_double(),
                                     col_double(),col_double(),col_double(),col_double(),col_double(),
                                     col_factor(),col_factor()))

set_2 <- read_delim("Test.txt", delim=",",col_names = c("duration","protocol_type",
                                                        "service","flag","src_bytes",
                                                        "dst_bytes","land", "wrong_fragment",
                                                        "urgent","hot","num_failed_logins",
                                                        "logged_in", "num_compromised",
                                                        "root_shell","su_attempted","num_root",
                                                        "num_file_creations","num_shells",
                                                        "num_access_files","num_outbound_cmds",
                                                        "is_hot_login", "is_guest_login","count",
                                                        "srv_count","serror_rate", "srv_serror_rate",
                                                        "rerror_rate","srv_rerror_rate","same_srv_rate",
                                                        "diff_srv_rate", "srv_diff_host_rate",
                                                        "dst_host_count","dst_host_srv_count",
                                                        "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                                                        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                                                        "dst_host_serror_rate","dst_host_srv_serror_rate",
                                                        "dst_host_rerror_rate","dst_host_srv_rerror_rate",
                                                        "attack", "last_flag"),
                    col_types = list(col_double(),col_factor(),col_factor(),col_factor(),col_integer(),col_integer(),
                                     col_factor(),col_integer(),col_integer(),col_integer(),col_integer(),
                                     col_factor(),col_integer(),col_factor(),col_integer(),col_integer(),
                                     col_integer(),col_integer(),col_integer(),col_integer(),col_factor(),
                                     col_factor(),col_integer(),col_integer(),col_double(),col_double(),
                                     col_double(),col_double(),col_double(),col_double(),col_double(),
                                     col_integer(),col_integer(),col_double(),col_double(),col_double(),
                                     col_double(),col_double(),col_double(),col_double(),col_double(),
                                     col_factor(),col_factor()))

#Joining the two datasets
set <- rbind.data.frame(set_1,set_2)

#Removing the last column (last_flag) as it will not be used
set <- set[-43]

#Creating detect column for binomial classification
set <- set %>% mutate(detect= ifelse(attack=="normal","normal","abnormal"))%>%
  mutate(detect = as.factor(detect))

#Creating attack_class column for attack class classification
set <- set %>% mutate(attack_class = ifelse(attack=="back"|attack=="land"|attack=="neptune"|attack=="pod"|attack=="smurf"|attack=="teardrop"|attack=="apache2"|attack=="udpstorm"|attack=="processtable"|attack=="worm"|attack=="mailbomb","dos",
                                            ifelse(attack=="satan"|attack=="ipsweep"|attack=="nmap"|attack=="portsweep"|attack=="mscan"|attack=="saint","probe",
                                                   ifelse(attack=="guess_passwd"|attack=="ftp_write"|attack=="imap"|attack=="phf"|attack=="multihop"|attack=="warezmaster"|attack=="warezclient"|attack=="spy"|attack=="xlock"|attack=="xsnoop"|attack=="snmpguess"|attack=="snmpgetattack"|attack=="httptunnel"|attack=="sendmail"|attack=="named","r2l",
                                                          ifelse(attack=="buffer_overflow"|attack=="loadmodule"|attack=="rootkit"|attack=="perl"|attack=="sqlattack"|attack=="xterm"|attack=="ps","u2r","normal"))))) 

#Setting levels for attacks
set$attack <- factor(set$attack,levels(factor(set$attack))[c(1,11,20,2,10,9,6,26,40,28,36,32,8,4,7,5,25,24,12,13,17,19,14,18,3,22,37,38,31,27,29,34,33,16,21,15,23,39,35,30)])

#Setting levels for attack class
set$attack_class <- factor(set$attack_class,levels(factor(set$attack_class))[c(2,1,3,4,5)])

#Setting levels for attack
set$detect <- factor(set$detect,levels(factor(set$detect))[c(2,1)])

#partititioning Data into edx and validation sets
set.seed(1, sample.kind="Rounding")
validation_index_edx <- createDataPartition(y = set$attack_class, times = 1, p = 0.1, list = FALSE)
edx_set <- set[-validation_index_edx,]
validation_set <- set[validation_index_edx,]

#Removing Column 20 as it has all values equal to 0
edx_set <- edx_set[,-20]

#Seperating out numerical and categorical data
num_edx <- as.data.frame(edx_set[,sapply(edx_set, is.numeric)])
#Seperating out numerical and categorical data
cat_edx <- as.data.frame(edx_set[,!sapply(edx_set, is.numeric)])%>%
  select(-c(attack, detect, attack_class))
#Seperating out numerical and categorical data
edx <- edx_set %>% select(-c(attack, detect, attack_class))


#Creating Train and Test subsets from edx set
set.seed(1, sample.kind="Rounding")
train_index <- createDataPartition(y = edx_set$attack, times = 1, p = 0.8, list = FALSE)
train_set <- edx_set[train_index,]
test_set <- edx_set[-train_index,]

#Filtering out numerical predictors
num_train <- as.data.frame(train_set[,sapply(train_set, is.numeric)])
num_test <- as.data.frame(test_set[,sapply(test_set, is.numeric)])

#Filtering out categorical predictors
cat_train <- as.data.frame(train_set[,!sapply(train_set, is.numeric)])%>% 
  select(-c(attack, detect, attack_class))
cat_test <- as.data.frame(test_set[,!sapply(test_set, is.numeric)])%>%
  select(-c(attack, detect, attack_class))


# Standardizing numerical data on Anomaly and classify datasets
mean_train <- apply(num_train, 2, function(x){mean(x)})
sd_train <- apply(num_train, 2, function(x){sd(x)})
std_features <- apply(num_train,2,function(x){(x-mean(x))/(sd(x))})

# Performing PCA on all datatypes using the 'PCAmix' function 
pca_mix<-PCAmixdata::PCAmix(X.quanti=num_edx,X.quali=cat_edx,rename.level=TRUE,graph=FALSE)

# Displaying the number of dimensions needed to explain 90% of the  variance
variance_explained <- pca_mix$eig[,3]
num_dimensions <- c(1:nrow(pca_mix$eig))
pca_mix$eig[80:85,] %>% knitr::kable()

#Performing SVD-PCA on numerical features
pc <- prcomp(std_features, center = F, scale. = F)
var_explained <- cumsum(pc$sdev^2/sum(pc$sdev^2))

# Displaying the cumulative proportions of variance explained by each dimension
var_explained

# Plotting the variance explained
plot(var_explained)

#Chosing the first 16 principal components
train.data <- data.frame(train_set[,!sapply(train_set, is.numeric)], pc$x[,1:16])

#Train Set for Anomaly detection
train.data_detect <- train.data %>% select(-c(attack, attack_class))

#Train Set for attack detection
train.data_attack_class <- train.data %>% select(-c(attack, detect))

#Selecting only numerical features
num_test <- as.data.frame(test_set[,sapply(test_set, is.numeric)])

#Centering and Scaling the test set using the mean and Sd of train set
std_features_test <- mapply(function(x,y,z){(x-y)/z},num_test,mean_train,sd_train)

# transform test into PCA
test.data <- predict(pc, std_features_test)
test.data <- data.frame(test_set[,!sapply(test_set, is.numeric)],test.data[,1:16])
test.data <- test.data %>% select(-c(attack, attack_class, detect))


options(digits=4, scipen=999)

#Using Random Forest for Network Anomaly Detection
train_rf_detect <- ranger(detect ~ .,
                          data = train.data_detect)

#Making predictions
pred_rf_detect <- predict(train_rf_detect, data = test.data)$predictions

#Getting Accuracy
a1 <- confusionMatrix(pred_rf_detect,
                      test_set$detect)$overall["Accuracy"]

#Getting Sensitivity
se1<- confusionMatrix(pred_rf_detect,
                      test_set$detect)$byClass["Sensitivity"]

#Getting Specificity
sp1 <- confusionMatrix(pred_rf_detect,
                       test_set$detect)$byClass["Specificity"]

results_rf_detect <- data_frame(Goal = "Anomaly Detection",
                                Method = "Random Forest",
                                Accuracy = a1, Sensitivity = se1, Specificity = sp1)

# DIsplaying results
data.frame(results_rf_detect) %>% knitr::kable()


#Using Random Forest for Network Anomaly Classification
#Training
train_rf_attack_classify <- ranger(attack_class ~ ., data = train.data_attack_class)

# Making predictions and getting the Accuracy
a3 <- confusionMatrix(predict(train_rf_attack_classify, data = test.data)$predictions, test_set$attack_class)$overall["Accuracy"]
results_rf_classify <- data_frame(Goal = "Attack Classification", Method = "Random Forest", Accuracy = a3)

#Displaying
data.frame(results_rf_classify) %>% knitr::kable()

#Using Random Tree for Network Anomaly Detection

#Training
train_rpart_detect <- train(detect ~ ., 
                            method = "rpart",
                            tuneGrid = data.frame(cp = 0),
                            data = train.data_detect)

#Making predictions
pred_rpart_detect <- predict(train_rpart_detect, test.data)

#Getting Accuracy
a2 <- confusionMatrix(pred_rpart_detect,
                      test_set$detect)$overall["Accuracy"]

#Getting Sensitivity
se2 <- confusionMatrix(pred_rpart_detect,
                       test_set$detect)$byClass[("Sensitivity")]

#Getting Specificity
sp2 <- confusionMatrix(pred_rpart_detect,
                       test_set$detect)$byClass[("Specificity")]

results_rpart_detect <- data_frame(Goal = "Anomaly Detection",
                                   Method = "Decision Tree",
                                   Accuracy = a2,
                                   Sensitivity = se2,
                                   Specificity = sp2)

#Displaying the results
data.frame(results_rpart_detect) %>% knitr::kable()

#Using Random Tree for Network Anomaly Classification

# Training
train_rpart_attack_classify <- train(attack_class ~ ., 
                                     method = "rpart",
                                     tuneGrid = data.frame(cp = 0),
                                     data = train.data_attack_class)


# Making predictions and getting the Accuracy
a4 <- confusionMatrix(predict(train_rpart_attack_classify, test.data), test_set$attack_class)$overall["Accuracy"]
results_rpart_classify <- data_frame(Goal = "Attack Classification", Method = "Decision Tree", Accuracy = a4)

#Displaying
data.frame(results_rpart_classify) %>% knitr::kable()


#FIltering out the numerical features of the edx set
num_edx <- as.data.frame(edx_set[,sapply(edx_set, is.numeric)])

#Standardizing the numerical features of edx_set
mean_edx <- apply(num_edx, 2, function(x){mean(x)})
sd_edx <- apply(num_edx, 2, function(x){sd(x)})
std_features_edx <- apply(num_edx,2,function(x){(x-mean(x))/(sd(x))})

# Perfroming PCA on the standardized numerical features of Edx set
pc <- prcomp(std_features_edx, scale. = F, center = F)

#Chosing only the first 16 principal components
edx.data <- data.frame(edx_set[,!sapply(edx_set, is.numeric)], pc$x[,1:16])

#Final edx set for Anomaly detection
edx.data_detect <- edx.data %>% select(-c(attack, attack_class))

#FInal edx set for Attack classification
edx.data_attack_class <- edx.data %>% select(-c(attack, detect))

#Removing column 20 i.e num_outnound_cmds as we did for the edx set
validation_set <- validation_set[,-20]

#Selecting only numerical features
num_validation <- as.data.frame(validation_set[,sapply(validation_set, is.numeric)])

#Centering and Scaling the test set using the mean and Sd of the edx sets
std_features_validation <- mapply(function(x,y,z){(x-y)/z},num_validation,mean_edx,sd_edx)

# Predict Principal Components of the Validation set
validation.data <- predict(pc, std_features_validation)

# Combining the first 16 dimensions of the predicted principal components with the rest of the non-numeric categories
validation.data <- data.frame(validation_set[,!sapply(validation_set, is.numeric)],validation.data[,1:16])
validation.data_detect <- validation.data %>% select(-c(attack, attack_class))


#Training the model
edx_rf_detect <- ranger(detect ~ ., data = edx.data_detect)

#Making predictions
pred_detect <- predict(edx_rf_detect, data = validation.data)$predictions

#Getting Accuracy
acc_detect <- confusionMatrix(pred_detect,
                              validation_set$detect)$overall["Accuracy"]

#Getting Sensitivity
sen_detect <- confusionMatrix(pred_detect,
                              validation_set$detect)$byClass["Sensitivity"]

#Getting Specificity
spec_detect <- confusionMatrix(pred_detect,
                               validation_set$detect)$byClass["Specificity"]

#Displaying results
results_detect <- data_frame(Goal = "Anomaly Detection",
                             Accuracy = acc_detect,
                             Sensitivity = sen_detect,
                             Specificity = spec_detect)
data.frame(results_detect) %>% knitr::kable()

#Training the model
edx_rf_attack_classify <- ranger(attack_class ~ ., data = edx.data_attack_class)

#Making predictions and getting Accuracy value
acc_classify <- confusionMatrix(predict(edx_rf_attack_classify, data = validation.data)$predictions,
                                validation_set$attack_class)$overall["Accuracy"]

results_classify <- data_frame(Goal = "Attack Classification",
                               Accuracy = acc_classify)

#Displaying results
data.frame(results_classify) %>% knitr::kable()
