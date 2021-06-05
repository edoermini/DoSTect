import numpy as np
from scipy import optimize
import matplotlib.pyplot as plt
from scipy.optimize import least_squares
import sys
import random

def expo (series,alpha):

    prediction = np.array([series[0]])
    for n in range(1,len(series)):
        new_val = np.array([alpha*series[n] + (1 - alpha) * prediction[n-1]])
        prediction = np.append(prediction,new_val)
    return alpha*series[n] + (1 - alpha) * prediction[n]

def expo1 (series,alpha):

    prediction = [series[0]]
    for n in range(1,len(series)):
        new_val = alpha*series[n] + (1 - alpha) * prediction[n-1]
        prediction.append(new_val)
    
    prediction.append(alpha*series[n] + (1 - alpha) * prediction[n])
    return prediction

def expo2(series,alpha,beta):
    result = np.array([series[0]])
    for n in range(1,len(series)):
        if n == 1:
            level, trend = series[0], series[1] - series[0]
        if n >= len(series):
            value = result[-1]
        else:
            value = series[n]

        last_level, level = level, alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (level - last_level) + (1 - beta) * trend
        result = np.append(result,np.array([level + trend]))

    return result[len(result) - 1]

def expo3(series,alpha,beta):
    print("Alpha: ", alpha)
    print("Beta: ", beta)
    print()

    result = np.array([series[0]])
    trend = 0
    level = 0
    for n in range(1,len(series)):
        if n == 1:
            level, trend = series[0], series[1] - series[0]
        if n >= len(series):
            value = result[-1]
        else:
            value = series[n]

        last_level, level = level, alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (level - last_level) + (1 - beta) * trend
        result = np.append(result,np.array([level + trend]))

    return result

def sse(values, predictions):
    print("ciao")
    try:
        s = 0
        for n, r in zip(values, predictions):
            s = s + (n - r) ** 2
        return s
    except OverflowError:
        return sys.float_info.max

x2 = np.array([

2.943750000000002e-08 ,
2.6380609244375015e-08 ,
0.00033778676361512076, 
7.877894753308609 ,
7.62125411372399 ,
7.118045067231843 ,
6.634036072752719,
5.093960579074693 ,
3.227375223823412,
2.8980883651420726,
7.62125411372399 ,
2.739084320724892 ,
])

#x0 = np.array([3, 3.7, 4.53, 5.377, 6.0393, 6.43537, 6.991833])
x0 = np.array([0, 3, 3.77, 4.53, 5.377, 6.0393, 6.43537, 6.991833, 7.39, 6.59, 8.88])
print(expo3(x0,0,0))
x = [round(random.uniform(0,1),3), round(random.uniform(0,1),3)]
print("Alpha iniziale: " + str(x[0]))
print("Beta iniziale: " + str(x[1]))

#x = np.array([random.random(),random.random()])

bounds = ((0,1),(0,1))
fun = lambda x: sse(x2,expo3(x2,x[0],x[1]))
fun0 = lambda x: sse(x0,expo3(x0,x[0],x[1]))


x1 = [0, 3, 3.77, 4.53, 5.377, 6.0393, 6.43537, 6.991833, 7.39, 6.59, 8.88, 9.21]




#res = optimize.minimize(fun,x0=x,method='nelder-mead',options={'xatol':1e-8, 'disp': True})
#res = least_squares(fun,x,bounds = bound)
res = optimize.minimize(fun,x0=x,method='SLSQP',bounds=bounds)
#res2 = optimize.minimize(fun, x0=x, method='TNC', bounds=bounds)


#plt.plot(res.x,'bo')
plt.plot(x2,'bo')
plt.plot(expo3(x2,res.x[0],res.x[1]),'r-')
plt.show()
#a = (res.x[-1] - res.x[-2]) / (x0[-1]-res.x[-2])
print('{0:.16f}'.format(res.x[0]))
print('{0:.16f}'.format(res.x[1]))

'''
plt.plot(x0,'bo')
plt.plot(expo3(x2,res2.x[0],res2.x[1]),'r-')
plt.show()
#a = (res.x[-1] - res.x[-2]) / (x0[-1]-res.x[-2])
print('{0:.16f}'.format(res2.x[0]))
print('{0:.16f}'.format(res2.x[1]))
'''