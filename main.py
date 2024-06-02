import os
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from openai import OpenAI
from pydantic import BaseModel
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime

app = FastAPI()
security = HTTPBasic()

openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
assistants = openai_client.beta

assistant_ids = {"Tech_Support": "asst_C6FGisxxWVFAJR7Hg2iDOviw"}

class AskRequest(BaseModel):
    question: str
    thread_id: str

def retrieve_ticket():
    email = "admin@proco.link"
    password = "admin"

    # Define the URL and the payload for the token request
    token_url = "https://helpdesk-app-api-production.up.railway.app/api/user/token/"
    payload = {
        "email": email,
        "password": password
    }

    # Make the POST request to get the token
    token_response = requests.post(token_url, json=payload)

    # Check if the request was successful
    if token_response.status_code == 200:
        # Extract the token from the response
        token = token_response.json().get("token")
        print(token)

        # Authorize using the token
        headers = {
            "Authorization": f"Token {token}",
            "accept": "application/json"
        }

        # Use the token to retrieve tickets
        tickets_url = "https://helpdesk-app-api-production.up.railway.app/api/ticket/tickets/"
        tickets_response = requests.get(tickets_url, headers=headers)

        # Check if the request was successful
        if tickets_response.status_code == 200:
            # Extract title and description from tickets data
            tickets = tickets_response.json()
            simplified_tickets = [{"title": ticket["title"], "description": ticket["description"], "summary": ticket["summary"],} for ticket in tickets]
            return simplified_tickets
    else:
        print("Failed to retrieve token:", token_response.status_code, token_response.text)
        return None

tickets = retrieve_ticket()
if tickets:
    print(tickets)

def create_new_ticket(title, summary):
    email = "admin@proco.link"
    password = "admin"

    # Define the URL and the payload for the token request
    token_url = "https://helpdesk-app-api-production.up.railway.app/api/user/token/"
    payload = {
        "email": email,
        "password": password
    }

    # Make the POST request to get the token
    token_response = requests.post(token_url, json=payload)

    # Check if the request was successful
    if token_response.status_code == 200:
        # Extract the token from the response
        token = token_response.json().get("token")
        print(token)

        # Authorize using the token
        headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json"
        }

        # Define the URL and the payload for creating a new ticket
        ticket_url = "https://helpdesk-app-api-production.up.railway.app/api/ticket/tickets/"
        ticket_payload = {
            "due_at": datetime.now().isoformat(),
            "closed_at": datetime.now().isoformat(),
            "closed_by": "user_id_string",  # Replace with actual user ID if applicable
            "title": title,
            "description": "Sample Ticket Description",
            "summary": summary,
            "status": "open",
            "priority": 1
        }

        # Make the POST request to create the new ticket
        ticket_response = requests.post(ticket_url, headers=headers, json=ticket_payload)

        # Check if the request was successful
        if ticket_response.status_code == 201:
            print("Ticket created successfully")
            return ticket_response.json()
        else:
            print("Failed to create ticket:", ticket_response.status_code, ticket_response.text)
            return None
    else:
        print("Failed to retrieve token:", token_response.status_code, token_response.text)
        return None

def get_current_username(
        credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = os.environ["BASIC_AUTH_USERNAME"]
    correct_password = os.environ["BASIC_AUTH_PASSWORD"]
    if not (credentials.username == correct_username
            and credentials.password == correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/")
async def root(username: str = Depends(get_current_username)):
    return {"message": "Hello World"}


@app.post("/ask")
async def ask_openai(request: AskRequest,
                     username: str = Depends(get_current_username)):
    question = request.question
    thread_id = request.thread_id

    # Add the new message to the existing thread
    assistants.threads.messages.create(thread_id=thread_id,
                                       role="user",
                                       content=question)

    run = assistants.threads.runs.create_and_poll(
        thread_id=thread_id,
        assistant_id=assistant_ids['Tech_Support'],
    )

    if run.status == "completed":
        messages = assistants.threads.messages.list(thread_id=thread_id)
        return {"response": messages.data[0].content[0]}
    else:
        print(run.status)

    tool_outputs = []

    if run.required_action and run.required_action.submit_tool_outputs:
        for tool in run.required_action.submit_tool_outputs.tool_calls:
            if tool.function.name == "test":
                # code

                tool_outputs.append({
                    "tool_call_id": tool.id,
                    "output": "okay nice"
                })

        # Submit all tool outputs at once after collecting them in a list
        if tool_outputs:
            try:
                run = assistants.threads.runs.submit_tool_outputs_and_poll(
                    thread_id=thread_id,
                    run_id=run.id,
                    tool_outputs=tool_outputs)
                print("Tool outputs submitted successfully.")
            except Exception as e:
                print("Failed to submit tool outputs:", e)
        else:
            print("No tool outputs to submit.")
    else:
        print("No required action or submit tool outputs found.")

    if run.status == "completed":
        messages = assistants.threads.messages.list(thread_id=thread_id)
        return {"response": messages.data[0].content[0]}
    else:
        print(run.status)

@app.post("/FunctionCalling")
async def function_calling(request: AskRequest):
    question = request.question
    thread_id = request.thread_id

    # Add the new message to the existing thread
    assistants.threads.messages.create(thread_id=thread_id, role="user", content=question)

    run = assistants.threads.runs.create_and_poll(
        thread_id=thread_id,
        assistant_id=assistant_ids['Tech_Support'],
    )

    #Retrive Ticket Function
    def retrieve_ticket():
        email = "admin@proco.link"
        password = "admin"

        # Define the URL and the payload for the token request
        token_url = "https://helpdesk-app-api-production.up.railway.app/api/user/token/"
        payload = {
            "email": email,
            "password": password
        }

        # Make the POST request to get the token
        token_response = requests.post(token_url, json=payload)

        # Check if the request was successful
        if token_response.status_code == 200:
            # Extract the token from the response
            token = token_response.json().get("token")
            print(token)

            # Authorize using the token
            headers = {
                "Authorization": f"Token {token}",
                "accept": "application/json"
            }

            # Use the token to retrieve tickets
            tickets_url = "https://helpdesk-app-api-production.up.railway.app/api/ticket/tickets/"
            tickets_response = requests.get(tickets_url, headers=headers)

            # Check if the request was successful
            if tickets_response.status_code == 200:
                # Extract title and description from tickets data
                tickets = tickets_response.json()
                simplified_tickets = [{"title": ticket["title"], "description": ticket["description"]} for ticket in tickets]
                return simplified_tickets
            else:
                print("Failed to retrieve tickets:", tickets_response.status_code, tickets_response.text)
                return None
        else:
            print("Failed to retrieve token:", token_response.status_code, token_response.text)
            return None

    #Create New Ticket Function
    def create_new_ticket(title, summary):
        email = "admin@proco.link"
        password = "admin"

        # Define the URL and the payload for the token request
        token_url = "https://helpdesk-app-api-production.up.railway.app/api/user/token/"
        payload = {
            "email": email,
            "password": password
        }

        # Make the POST request to get the token
        token_response = requests.post(token_url, json=payload)

        # Check if the request was successful
        if token_response.status_code == 200:
            # Extract the token from the response
            token = token_response.json().get("token")
            print(token)

            # Authorize using the token
            headers = {
                "Authorization": f"Token {token}",
                "Content-Type": "application/json"
            }

            # Define the URL and the payload for creating a new ticket
            ticket_url = "https://helpdesk-app-api-production.up.railway.app/api/ticket/tickets/"
            ticket_payload = {
                "due_at": datetime.now().isoformat(),
                "closed_at": datetime.now().isoformat(),
                "closed_by": "user_id_string",  # Replace with actual user ID if applicable
                "title": title,
                "description": "Sample Ticket Description",
                "summary": summary,
                "status": "open",
                "priority": 1
            }

            # Make the POST request to create the new ticket
            ticket_response = requests.post(ticket_url, headers=headers, json=ticket_payload)

            # Check if the request was successful
            if ticket_response.status_code == 201:
                print("Ticket created successfully")
                return ticket_response.json()
            else:
                print("Failed to create ticket:", ticket_response.status_code, ticket_response.text)
                return None
        else:
            print("Failed to retrieve token:", token_response.status_code, token_response.text)
            return None

    #Update Ticket Function

    # Escalation Function
    def escalate_to_human_chat(name):
        print("Escalating " + name + " chat to a human")
        send_email(name)

    # Get Customer Info Function
    def get_customer_info(phone_number, name):
        print("Got customer's info, Name: " + name + " Phone Number: " + phone_number)
        send_email(name, phone_number)

    # Email sending function
    def send_email(name, phone_number=None):
        sender_email = "marcusbusinessmanage@gmail.com"
        receiver_email = "mswy07@gmail.com"
        password = "ucnw yslg kbxt pftc"

        message = MIMEMultipart("alternative")
        message["Subject"] = "Escalation Alert"
        message["From"] = sender_email
        message["To"] = receiver_email

        text = f"Escalation alert: {name}'s chat needs human chat intervention."

        if phone_number:
            text = f"Escalation alert: {name}'s chat needs human call intervention. \n\nPhone Number: {phone_number}"
            
        part = MIMEText(text, "plain")

        message.attach(part)

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())
                print("Email sent successfully")
        except Exception as e:
            print(f"Failed to send email: {e}")

    if run.status == "completed":
        messages = assistants.threads.messages.list(thread_id=thread_id)
        return {"response": messages.data[0].content[0]}
    else:
        print(run.status)

    tool_outputs = []

    if run.required_action and run.required_action.submit_tool_outputs:
        for tool in run.required_action.submit_tool_outputs.tool_calls:
            function_name = tool.function.name
            arguments = json.loads(tool.function.arguments)
            print("Function Name: " + function_name)

            if function_name == "get_customer_info":
                phone_number = arguments["phone_number"]
                name = arguments["name"]
                get_customer_info(phone_number, name)
                # Only handle the first required action to prevent multiple function calls
                tool_outputs.append({
                    "tool_call_id": tool.id,
                    "output": f"Handled by {function_name}"
                })
                break
            elif function_name == "escalate_to_human_chat":
                name = arguments["name"]
                escalate_to_human_chat(name)
                tool_outputs.append({
                    "tool_call_id": tool.id,
                    "output": f"Handled by {function_name}"
                })
                break
            elif function_name == "retrieve_ticket":
                tickets = retrieve_ticket()
                if tickets:
                    # Convert tickets list to string
                    tickets_output = "\n".join([f"Title: {ticket['title']}, Description: {ticket['description']}" for ticket in tickets])
                    tool_outputs.append({
                        "tool_call_id": tool.id,
                        "output": tickets_output
                    })
                else:
                    tool_outputs.append({
                        "tool_call_id": tool.id,
                        "output": "Failed to retrieve tickets"
                    })
                break
            elif function_name == "create_new_ticket":
                title = arguments["title"]
                summary = arguments["summary"]
                new_ticket = create_new_ticket(title, summary)
                if new_ticket:
                    tool_outputs.append({
                        "tool_call_id": tool.id,
                        "output": "Ticket created successfully"
                    })
                else:
                    tool_outputs.append({
                        "tool_call_id": tool.id,
                        "output": "Failed to create ticket"
                    })
                break

        # Submit all tool outputs at once after collecting them in a list
        if tool_outputs:
            try:
                run = assistants.threads.runs.submit_tool_outputs_and_poll(
                    thread_id=thread_id,
                    run_id=run.id,
                    tool_outputs=tool_outputs)
                print("Tool outputs submitted successfully.")
            except Exception as e:
                print("Failed to submit tool outputs:", e)
        else:
            print("No tool outputs to submit.")
    else:
        print("No required action or submit tool outputs found.")

    if run.status == "completed":
        messages = assistants.threads.messages.list(thread_id=thread_id)
        return {"response": messages.data[0].content[0]}
    else:
        print(run.status)

@app.get("/id")
async def generate_thread(username: str = Depends(get_current_username)):
    thread = assistants.threads.create()
    thread_id = thread.id
    return {"thread_id": thread_id}
