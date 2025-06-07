import requests
import webbrowser
import urllib.parse

def send_whatsapp_otp(phone_number, otp):
    """
    Send OTP via WhatsApp using the WhatsApp click-to-chat feature
    phone_number: The recipient's phone number (with country code, e.g., '911234567890')
    otp: The OTP to send
    """
    # Format the phone number (remove any spaces or special characters)
    phone_number = ''.join(filter(str.isdigit, phone_number))
    
    # Create the message
    message = f"Your OTP for login is: {otp}. This OTP is valid for 5 minutes. Do not share this OTP with anyone."
    
    # Encode the message for URL
    encoded_message = urllib.parse.quote(message)
    
    # Create the WhatsApp click-to-chat URL
    whatsapp_url = f"https://wa.me/{phone_number}?text={encoded_message}"
    
    try:
        # Open the WhatsApp URL in the default browser
        webbrowser.open(whatsapp_url)
        print(f"\nOTP: {otp}")
        print("A WhatsApp window should open in your browser.")
        print("Click 'Continue to Chat' and then 'Send' to deliver the OTP.")
        return True, "WhatsApp window opened successfully"
    except Exception as e:
        return False, f"Error opening WhatsApp: {str(e)}" 