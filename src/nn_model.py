from typing import List
import torch
import torch.nn as nn
import pandas as pd
import torch.utils.data as data_utils

class NeuralNetworkModel(nn.Module):
    def __init__(
            self, 
            input_size: int, 
            output_size: int, 
            lr:float=0.001, 
            number_of_hidden_layers: int = 6,
            dense_layer_size: int=64, 
            device: torch.device=torch.device("cpu")
            ):
        """ Implimentation of a neural network using pytorch 

        Args:
            input_size (int): Number of perceptrons in the first layer of the network (length of input data)
            output_size (int): Number of perceptrons in the final layer of the network (number of classes)
            lr (float, optional): The learning rate of the model (higher learns quicker but can miss solutions). Defaults to 0.001.
            number_of_hidden_layers (int, optional): The number of layers of perceptrons in the model (higher means more complex model). Defaults to 6.
            dense_layer_size (int, optional): The number of perceptrons in each layer (higher means more complex model). Defaults to 64.
            device (torch.device, optional): The device to use for tensor calculations (set to gpu if avaliable). Defaults to torch.device("cpu").
        """
        
        super(NeuralNetworkModel, self).__init__()
        self.criterion = nn.CrossEntropyLoss()
        
        # build the input and output model layers plus a connecting ReLU layer 
        self.model_input_layer = nn.Linear(input_size, dense_layer_size)
        self.model_ReLU_layer = nn.ReLU()
        self.model_output_layer = nn.Linear(dense_layer_size, output_size)
        self.model_softmax_layer = nn.Softmax(dim=1)
        
        # build n hidden layers 
        self.model_layers = []
        for i in range(number_of_hidden_layers):
            self.model_layers.append(nn.Linear(dense_layer_size, dense_layer_size))
            self.model_layers.append(nn.ReLU())

        #self.optimizer = torch.optim.AdamW(self.parameters(), lr)
        self.optimizer = torch.optim.SGD(self.parameters(), lr=lr, momentum=0.9)
        self.device = device
    

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """ Gets the output of the model's neural network given an input

        Args:
            x (torch.Tensor): Input into the model's neural network

        Returns:
            torch.Tensor: The output of the model's neural network
        """
        # put x through the input layer
        x = self.model_input_layer(x)
        x = self.model_ReLU_layer(x)
        
        # put x through the hidden layers
        for model_layer in self.model_layers:
            x = model_layer(x)
        
        # put x through the output layer
        y = self.model_output_layer(x)
        y = self.model_softmax_layer(y)
        return y
    

    def predict(self, state: torch.Tensor) -> torch.Tensor:
        """ Gets the output of the model's neural network given an input without gradient propagation

        Args:
            state (torch.Tensor): Input into the model's neural network

        Returns:
            torch.Tensor: The output of the model's neural network
        """
        with torch.no_grad():
            return self.forward(state)
    
    
    def get_loss(self, predicted: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """ Calculates the loss between a set of predictions and truth labels

        Args:
            predicted (torch.Tensor): predictions from the model
            labels (torch.Tensor): truths from the dataset

        Returns:
            torch.Tensor: the loss (represents how good the models predictions are)
        """
        loss = self.criterion(predicted.float(), labels.float())
        
        return loss
        
        
    def back_propagate_loss(self, loss: torch.tensor):
        """ Propagates loss back through the model, updating weights and improving the predictions of the model

        Args:
            loss (torch.tensor): the loss of the model 
        """
        self.optimizer.step()
        

class NeuralNetwork:
    def __init__(self, input_size: int, output_size: int, device: torch.device=torch.device("cpu")):
        """ A class used to train a neural network for a classification problem 

        Args:
            input_size (int): The number of features 
            output_size (int): The number of classes
            device (torch.device, optional): The device to use for tensor calculations (set to gpu if avaliable). Defaults to torch.device("cpu").
        """
        self.model = NeuralNetworkModel(input_size=input_size, output_size=output_size)
        self.device = device
    

    def test(self, test_x: pd.DataFrame, test_y: pd.DataFrame) -> [float, torch.Tensor, torch.Tensor]:
        """ Tests the model of a set of tests x against the truths y

        Args:
            test_x (pd.DataFrame): The items to classify
            test_y (pd.DataFrame): The true classes of the items

        Returns:
            List[float, torch.Tensor, torch.Tensor]: The accuracy of the model, the actual predictions, the coresponding truths
        """
        x_tensor = torch.tensor(test_x.values.astype(float), device=self.device, dtype=torch.float32)
        y_tensor = torch.tensor(test_y.values.astype(int), device=self.device, dtype=torch.int64)
        
        pred = self.model(x_tensor)
        
        pred_class = torch.argmax(pred, dim=1)
        
        test_accuracy = torch.sum(pred_class == y_tensor).item() / y_tensor.size(0)
        
        return test_accuracy, pred_class, y_tensor
            
        
    def train(self, train_x: pd.DataFrame, train_y: pd.DataFrame, test_x: pd.DataFrame, test_y: pd.DataFrame, n_epochs: int=10, batch_size: int=64): 
        """ Trains the model on the given dataset

        Args:
            train_x (pd.DataFrame): Dataset of the items to classify (training)
            train_y (pd.DataFrame): The true classes of the items (training)
            test_x (pd.DataFrame): Dataset of the items to classify (testing)
            test_y (pd.DataFrame): The true classes of the items (testing)
            n_epochs (int, optional): The number of epochs to run the training for. Defaults to 10.
            batch_size (int, optional): The number of items per batch of training. Defaults to 64.
        """
        
        x_tensor = torch.tensor(train_x.values.astype(float), device=self.device, dtype=torch.float32)
        y_tensor = torch.tensor(train_y.values.astype(int), device=self.device, dtype=torch.int64)
        
        # convert the truths to a one hot encoding ([0, 1, 1, 0] -> [[1, 0], [0, 1], [0, 1], [1, 0]])
        # becuase model output is n neurons representing the probability it thinks it belongs to that class
        y_tensor = nn.functional.one_hot(y_tensor, 2)
        
        train = data_utils.TensorDataset(x_tensor, y_tensor)
        
        train_loader = data_utils.DataLoader(train, batch_size=batch_size, shuffle=True)
                
                
        for epoch in range(n_epochs):
            print("Epoch: ", epoch)
            
            running_loss = 0
            for batch_number, data in enumerate(train_loader, 0):
                
                # current batch
                x, y = data
                
                predictions = self.model(x)
                
                loss = self.model.get_loss(predictions, y)
                
                self.model.back_propagate_loss(loss)
                
                running_loss += loss.item()
            
            # prints the metrics on the current model
            print("Avg Mini-Batch Running Loss: ", running_loss/batch_number)
            test_accuracy, _, _ = self.test(test_x, test_y)
            print("Test Accuracy: ", test_accuracy)
                
    def save(self, name: str):
        """ Save the weights of the model for future use

        Args:
            name (str): The name to save the model under
        """
        torch.save(self.model.state_dict(), name)
                