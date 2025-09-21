"""
Email Templates for Manpower Platform
Provides HTML and text email templates for various notification types
"""

def get_base_template():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
            background: linear-gradient(135deg, #d4af37, #b8941f);
            color: #000;
            padding: 30px 40px;
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            font-family: 'Playfair Display', serif;
            margin-bottom: 10px;
        }
        .tagline {
            font-size: 14px;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .content {
            padding: 40px;
        }
        .title {
            font-size: 24px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 20px;
        }
        .message {
            font-size: 16px;
            color: #555;
            margin-bottom: 30px;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #d4af37, #b8941f);
            color: #000;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
        }
        .details {
            background-color: #f8f9fa;
            border-left: 4px solid #d4af37;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .footer {
            background-color: #1a1a1a;
            color: #ccc;
            padding: 30px 40px;
            text-align: center;
            font-size: 14px;
        }
        .footer a {
            color: #d4af37;
            text-decoration: none;
        }
        .unsubscribe {
            margin-top: 20px;
            font-size: 12px;
            color: #999;
        }
        @media (max-width: 600px) {
            .container {
                margin: 0;
                box-shadow: none;
            }
            .header, .content, .footer {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ManPower</div>
            <div class="tagline">Professional Workforce Solutions</div>
        </div>
        <div class="content">
            {{content}}
        </div>
        <div class="footer">
            <p>© 2024 ManPower Platform. All rights reserved.</p>
            <p>
                <a href="{{platform_url}}/dashboard">Visit Dashboard</a> | 
                <a href="{{platform_url}}/support">Support</a> | 
                <a href="{{platform_url}}/unsubscribe?token={{unsubscribe_token}}">Unsubscribe</a>
            </p>
            <div class="unsubscribe">
                You received this email because you have an account with ManPower Platform.
                <br>If you no longer wish to receive these emails, you can unsubscribe above.
            </div>
        </div>
    </div>
</body>
</html>
"""

def welcome_email_template(user_name, user_role):
    content = f"""
        <h1 class="title">Welcome to ManPower Platform, {user_name}!</h1>
        <div class="message">
            <p>Thank you for joining ManPower Platform as a <strong>{user_role.title()}</strong>. We're excited to have you as part of our professional workforce community.</p>
            
            <p>Here's what you can do next:</p>
            <ul>
                <li>Complete your profile to increase your visibility</li>
                <li>{"Browse available contracts and apply to those that match your skills" if user_role == "individual" else "Post your first contract to find qualified workers" if user_role == "business" else "Explore partnership opportunities and manage your workforce"}</li>
                <li>Set up your notification preferences</li>
                <li>Verify your account for increased trust</li>
            </ul>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard" class="button">Get Started</a>
        </div>
        
        <div class="details">
            <h3>Quick Tips:</h3>
            <p>• Keep your profile updated with your latest skills and experience</p>
            <p>• Respond promptly to messages and applications</p>
            <p>• Maintain professional communication at all times</p>
            <p>• Use our dispute resolution system if any issues arise</p>
        </div>
    """
    return content

def contract_posted_template(contract_title, contract_id):
    content = f"""
        <h1 class="title">Contract Posted Successfully!</h1>
        <div class="message">
            <p>Your contract "<strong>{contract_title}</strong>" has been posted and is now live on the ManPower Platform.</p>
            <p>Qualified workers and agencies can now view and apply for your contract. You'll receive notifications when applications are submitted.</p>
        </div>
        
        <div class="details">
            <h3>Contract Details:</h3>
            <p><strong>Title:</strong> {contract_title}</p>
            <p><strong>Contract ID:</strong> #{contract_id}</p>
            <p><strong>Status:</strong> Open for Applications</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?contract={contract_id}" class="button">View Contract</a>
        </div>
        
        <div class="message">
            <p><strong>Next Steps:</strong></p>
            <ul>
                <li>Review incoming applications</li>
                <li>Use our AI matching system to find suitable candidates</li>
                <li>Communicate with applicants through our secure messaging</li>
                <li>Set up escrow payments for selected workers</li>
            </ul>
        </div>
    """
    return content

def application_received_template(applicant_name, contract_title, contract_id):
    content = f"""
        <h1 class="title">New Application Received!</h1>
        <div class="message">
            <p><strong>{applicant_name}</strong> has applied for your contract "<strong>{contract_title}</strong>".</p>
            <p>Review their profile, experience, and proposal to determine if they're a good fit for your project.</p>
        </div>
        
        <div class="details">
            <h3>Application Details:</h3>
            <p><strong>Applicant:</strong> {applicant_name}</p>
            <p><strong>Contract:</strong> {contract_title}</p>
            <p><strong>Applied:</strong> Just now</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?contract={contract_id}&tab=applications" class="button">Review Application</a>
        </div>
        
        <div class="message">
            <p><strong>Recommended Actions:</strong></p>
            <ul>
                <li>Review the applicant's profile and ratings</li>
                <li>Check their previous work history</li>
                <li>Send a message to discuss project details</li>
                <li>Schedule an interview if interested</li>
            </ul>
        </div>
    """
    return content

def message_received_template(sender_name, message_preview, conversation_id):
    content = f"""
        <h1 class="title">New Message from {sender_name}</h1>
        <div class="message">
            <p>You have received a new message on ManPower Platform.</p>
        </div>
        
        <div class="details">
            <h3>Message Preview:</h3>
            <p>"{message_preview[:150]}{'...' if len(message_preview) > 150 else ''}"</p>
            <p><strong>From:</strong> {sender_name}</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?chat={conversation_id}" class="button">Reply to Message</a>
        </div>
        
        <div class="message">
            <p>Stay connected with your network and respond promptly to maintain good professional relationships.</p>
        </div>
    """
    return content

def contract_status_update_template(contract_title, old_status, new_status, contract_id):
    content = f"""
        <h1 class="title">Contract Status Updated</h1>
        <div class="message">
            <p>The status of your contract "<strong>{contract_title}</strong>" has been updated.</p>
        </div>
        
        <div class="details">
            <h3>Status Change:</h3>
            <p><strong>Previous Status:</strong> {old_status.title()}</p>
            <p><strong>New Status:</strong> {new_status.title()}</p>
            <p><strong>Contract:</strong> {contract_title}</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?contract={contract_id}" class="button">View Contract</a>
        </div>
        
        <div class="message">
            <p>Keep track of your contract progress and ensure all milestones are met on time.</p>
        </div>
    """
    return content

def payment_notification_template(amount, contract_title, payment_type, contract_id):
    content = f"""
        <h1 class="title">Payment {payment_type.title()} Notification</h1>
        <div class="message">
            <p>A payment of <strong>${amount:,.2f}</strong> has been {payment_type} for contract "<strong>{contract_title}</strong>".</p>
        </div>
        
        <div class="details">
            <h3>Payment Details:</h3>
            <p><strong>Amount:</strong> ${amount:,.2f}</p>
            <p><strong>Contract:</strong> {contract_title}</p>
            <p><strong>Type:</strong> {payment_type.title()}</p>
            <p><strong>Date:</strong> {{"{{date}}"}}</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?contract={contract_id}&tab=payments" class="button">View Payment Details</a>
        </div>
        
        <div class="message">
            <p>All payments are processed securely through our escrow system to protect both parties.</p>
        </div>
    """
    return content

def verification_complete_template(user_name, verification_type):
    content = f"""
        <h1 class="title">Verification Complete!</h1>
        <div class="message">
            <p>Congratulations {user_name}! Your <strong>{verification_type}</strong> verification has been completed successfully.</p>
            <p>This verification badge will be displayed on your profile, increasing trust with potential clients and partners.</p>
        </div>
        
        <div class="details">
            <h3>Verification Details:</h3>
            <p><strong>Type:</strong> {verification_type}</p>
            <p><strong>Status:</strong> Verified ✓</p>
            <p><strong>Badge Earned:</strong> {verification_type} Verified</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard?tab=profile" class="button">View Profile</a>
        </div>
        
        <div class="message">
            <p>Verified users typically receive 40% more contract opportunities. Keep building your reputation!</p>
        </div>
    """
    return content

def weekly_digest_template(user_name, stats):
    content = f"""
        <h1 class="title">Your Weekly ManPower Digest</h1>
        <div class="message">
            <p>Hi {user_name}, here's your weekly summary of activity on ManPower Platform.</p>
        </div>
        
        <div class="details">
            <h3>This Week's Activity:</h3>
            <p><strong>New Contracts:</strong> {stats.get('new_contracts', 0)}</p>
            <p><strong>Applications Sent:</strong> {stats.get('applications_sent', 0)}</p>
            <p><strong>Messages Received:</strong> {stats.get('messages_received', 0)}</p>
            <p><strong>Profile Views:</strong> {stats.get('profile_views', 0)}</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{{{platform_url}}}}/dashboard" class="button">View Dashboard</a>
        </div>
        
        <div class="message">
            <p><strong>Trending This Week:</strong></p>
            <ul>
                <li>Construction projects are in high demand</li>
                <li>Security services seeing increased activity</li>
                <li>Remote work opportunities growing</li>
            </ul>
        </div>
    """
    return content

class EmailTemplateService:
    def __init__(self):
        self.base_template = get_base_template()
        self.platform_url = "http://localhost:5000"  # Update for production
    
    def render_template(self, content, title="ManPower Platform", unsubscribe_token=""):
        return self.base_template.replace("{{content}}", content).replace("{{title}}", title).replace("{{platform_url}}", self.platform_url).replace("{{unsubscribe_token}}", unsubscribe_token)
    
    def get_welcome_email(self, user_name, user_role, unsubscribe_token=""):
        content = welcome_email_template(user_name, user_role)
        return self.render_template(content, f"Welcome to ManPower Platform, {user_name}!", unsubscribe_token)
    
    def get_contract_posted_email(self, contract_title, contract_id, unsubscribe_token=""):
        content = contract_posted_template(contract_title, contract_id)
        return self.render_template(content, "Contract Posted Successfully", unsubscribe_token)
    
    def get_application_received_email(self, applicant_name, contract_title, contract_id, unsubscribe_token=""):
        content = application_received_template(applicant_name, contract_title, contract_id)
        return self.render_template(content, "New Application Received", unsubscribe_token)
    
    def get_message_received_email(self, sender_name, message_preview, conversation_id, unsubscribe_token=""):
        content = message_received_template(sender_name, message_preview, conversation_id)
        return self.render_template(content, f"New Message from {sender_name}", unsubscribe_token)
    
    def get_contract_status_email(self, contract_title, old_status, new_status, contract_id, unsubscribe_token=""):
        content = contract_status_update_template(contract_title, old_status, new_status, contract_id)
        return self.render_template(content, "Contract Status Updated", unsubscribe_token)
    
    def get_payment_notification_email(self, amount, contract_title, payment_type, contract_id, unsubscribe_token=""):
        content = payment_notification_template(amount, contract_title, payment_type, contract_id)
        return self.render_template(content, f"Payment {payment_type.title()} Notification", unsubscribe_token)
    
    def get_verification_complete_email(self, user_name, verification_type, unsubscribe_token=""):
        content = verification_complete_template(user_name, verification_type)
        return self.render_template(content, "Verification Complete!", unsubscribe_token)
    
    def get_weekly_digest_email(self, user_name, stats, unsubscribe_token=""):
        content = weekly_digest_template(user_name, stats)
        return self.render_template(content, "Your Weekly ManPower Digest", unsubscribe_token)

    def get_verification_email(self, user_name, verification_link):
        content = f"""
            <h1 class="title">Verify Your Email Address</h1>
            <div class="message">
                <p>Hello {user_name}! Thank you for joining ManPower Platform. To get started, please verify your email address by clicking the button below.</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_link}" class="button">Verify Email Address</a>
                </div>
                
                <p>If the button above does not work, you can also copy and paste this link into your browser:</p>
                <div class="details">
                    <p>{verification_link}</p>
                </div>
                
                <p><strong>Note:</strong> This verification link will expire in 24 hours for security purposes.</p>
            </div>
        """
        html = self.render_template(content, "Verify Your Email Address")
        text = f"""
Hello {user_name}!

Thank you for joining ManPower Platform. To get started, please verify your email address by clicking the link below:

{verification_link}

Note: This verification link will expire in 24 hours for security purposes.
        """
        return {'html': html, 'text': text}
