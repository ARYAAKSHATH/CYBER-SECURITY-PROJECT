import secrets
import string

class PasswordGenerator:
    """Utility class for generating secure passwords."""
    
    @staticmethod
    def generate_password(length=16, include_symbols=True, include_numbers=True,
include_uppercase=True, include_lowercase=True):
        """Generate a cryptographically secure random password."""
        if length < 4:
            length = 4
        if length > 128:
            length = 128
            
        characters = ""
        
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_letters + string.digits
        
        # Ensure password has at least one character from each selected category
        password = []
        if include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill the rest of the password
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def check_password_strength(password):
        """Check password strength and return score and feedback."""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")
            
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("Consider using 12+ characters for better security")
            
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Include lowercase letters")
            
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Include uppercase letters")
            
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Include numbers")
            
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Include special characters")
        
        strength_levels = {
            0: "Very Weak",
            1: "Very Weak", 
            2: "Weak",
            3: "Fair",
            4: "Good",
            5: "Strong",
            6: "Very Strong"
        }
        
        return {
            'score': score,
            'strength': strength_levels[score],
            'feedback': feedback
        }