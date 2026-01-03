from calculator import divide

try:
    result = divide(10, 0)
    print(f"Result: {result}")
except ZeroDivisionError as e:
    print(f"Caught exception: {e}")
