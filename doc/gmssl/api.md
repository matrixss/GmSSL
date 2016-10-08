## API Design



To design a complex C APIs for GmSSL is not an easy task. Here we follow some basic rules:





### Order of Function Arguments

In a cryptographic library, normally a function need these arguments: context, algorithm, parameters of algorithm, input and output. The context can be seen as the _this_ reference of the current object or instance. The algorithm can be cipher name. The parameters of algorithm are specific parameters for the algorithm, such as a cipher requires IV and key.

The GmSSL prefer the following order of arguments:

1. context
2. Algorithm (name). 
3. fixed parameters of the algorithm
4. input
5. output
6. parameters of algorithm

Following the function prototypes of OpenSSL, the GmSSL functions normally have two types of return values:

* The int value, 0 means error and 1 means success.
* Return a pointer of a created object. Return NULL means error.

If in the application scenario, the resources of the output will not be re-used many times, or the output is a complex object needs to be constructed for every different input, we will use returned new object instead of using output in the function arguments. When output is returned as return value, the order of arguments will be context, algorithm, input, and parameters of algorithm.

Sometimes the function (name) itself reflects the algorithm.

In different functions the OpenSSL use different input/output orders. For example, the EVP API use the output/input, the ECDSA use input/output, but ECDH use output/input again.









