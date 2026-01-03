from calculator import divide

# Test normal division
print("Testing 10 / 2:", divide(10, 2))

# Test division by zero
print("Testing 10 / 0:", divide(10, 0))

# Test negative numbers
print("Testing -5 / 2:", divide(-5, 2))

# Test zero divided by non-zero
print("Testing 0 / 5:", divide(0, 5))
