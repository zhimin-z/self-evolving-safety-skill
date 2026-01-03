def divide(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        print("Warning: Division by zero attempted")
        return None
