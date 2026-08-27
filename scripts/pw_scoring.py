def get_rating(score):
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Moderate"
    elif score < 90:
        return "Strong"
    else:
        return "Very Strong"

def entropy_to_score(zxcvbn_score):
    return zxcvbn_score * 25