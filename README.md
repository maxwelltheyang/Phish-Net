# Phish Net
A phishing detection software that combines various RESTful APIs to remove any harmful emails sent to the user. All of the phishing attributes used are in Phishing Websites Features.docx.

## Inspiration
Gmail's spam filtration method does not seem robust enough, I still get many emails that have phishing links. My goal is to develop a tool that filters out almost any phishing email to help people who are not as keen on spotting phishing emails to ensure that they do not have their information and property stolen.

## How it works
1) An email is sent to the user
2) A pub/sub is triggered and a GCloud function is run
3) Contents of the email are obtained by the gmail API
4) Attributes are extracted from the email 
5) Data values are run against a supervised machine learning model with around 2500 data points to predict if the website is phishing or save (with over 95% accuracy)
6) Email is moved to spam if there is a link deemed "phishing" in the contents of the email"

## File descriptions
Phishing Website Features.docx- All of the features extracted from a link and what they mean
phishing-domains.txt- A list of the most common phishing domains, used in process_email
phishing_ml.h5- Saved ML model
process_email.py- A local version of the cloud function, extracts email contents, obtain email attributes, run attributes with ML model, delete email if deemed "phishing"
process_email_gcloud.py- Same as previous file but uses Cloud Buckets instead of local files for Google Cloud use
save_token.py- Create OAuth2 Authentication token to allow Gmail API to access the user's inbox
scaler.save- Saved scaler file for the ML model
top-100000-domains.txt- Top 100,000 most popular website domains from Alexa, used in process_email
top-1000000-domains.txt- Top 1,000,000 most popular website domains from Alexa, used in process_email
uci-ml.py- Machine learning model created using supervised machine learning with neural networks (Scikit Learn)
watch_email-useracc.py- Script that sets up a watch on the user's inbox to notify the pub/sub when there is an incoming email. 

## Experience gained
I learned to work with many RESTful APIs, including Google Search, Gmail, and PageRank API. Many of the link attributes looked at the html contents of the website, such as favicon, external domains, and redirect links. I learned basic HTML and how to extract features uses request. Regular expressions were used to determine what an email pattern was like and how to extract only the links from an email. Used Google Cloud to automate the entire process, so I learned how to use Google Cloud Functions, Cloud Buckets, and Secret Manager to manage secrets such as API keys. 



