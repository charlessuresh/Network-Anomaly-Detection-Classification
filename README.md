# Network-Anomaly-Detection-Classification

With the increasing reliance on technology, it is becoming more and more essential to secure every aspect of online information and data. As the internet grows and computer networks become bigger, network security has become one of the most important aspects for organizations to consider. While there is no network that is immune to attacks, a stable and efficient network security system is essential to protecting data and for seamless operations.

To goal of this project was to build a network intrusion detection system that can do two things:

Detect whether a network acitivity is normal or is an attack (Binomial Classification)
To classify the type of network attack as: a) Normal b) DoS (Denial of Service) c) Probe d) R2L (Remote to Local/User) e) U2R (User to Root)
The dataset used for building the network intrusion detection system is from kaggle: https://www.kaggle.com/anushonkar/network-anamoly-detection

The available dataset is already split into Train and Test sets. However, the two sets were combined and split into 'edx' set and 'validation' set using the'createDataPartition' function to ensure even distrubition of different attack types. Algorithms were developed and tested by further splitting the 'edx' set into 'Train' and 'Test' sets. After selecting a suitable model, the entire 'edx' set was used to train the algorithm and make the final predictions on the 'validation' set. The metric used for assessing the models are:

For the Binomail Classifiction: Accuracy, Sensitivity and Specificity
For the Multinomial Classification: Accuracy
Because of the large number of features in the dataset, dimension reduction was attempted. Since substantial dimension reduction could not be achieved, Random Forest and Decision Trees, on account of being the most suited to datasets with high dimensions, were used.
