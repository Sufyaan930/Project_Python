import bcrypt
from cryptography.fernet import Fernet
import os
import json

encryption_key = Fernet.generate_key()
fernet = Fernet(encryption_key)

class User:
    def __init__(self,agent_id,username,password):
        self.agent_id=agent_id
        self.username=username
        self.password_hash=self.hash_password(password)
        self.tasks=[]


    def hash_password(self,password):
        salt=bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'),salt)
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password_hash)
    
    def add_task(self,task_description,due_date,classification_level):
        task = json.dumps({
            "description": task_description,
            "due_date": due_date,
            "classification": classification_level
        }).encode('utf-8')
        encrypted_task = fernet.encrypt(task)
        self.tasks.append(encrypted_task)
        print("Task added successfully!")

    def view_tasks(self):
        redacted_tasks = [{"description": "REDACTED", "due_date": "REDACTED", "classification": "REDACTED"} for _ in self.tasks]
        print("Tasks:", redacted_tasks)

    def view_sensitive_details(self, password):
        if not self.check_password(password):
            print("Invalid password!")
            return
        print("Decrypted Tasks:")
        for encrypted_task in self.tasks:
            decrypted_task = fernet.decrypt(encrypted_task).decode('utf-8')
            print(json.loads(decrypted_task))
    
def main():
        agent_id = input("Enter an ID: ")
        username = input("Please enter a username: ")
        password = input("Please enter a password: ")

        user = User(agent_id,username,password)

        while True:
            print("\nOptions: ")
            print("1. Add task")
            print("2. View Tasks")
            print("3. View sensitive details")
            print("4. Exit")
            choice = input("Choose an option: ")

            if choice == '1':
                task_description = input("Enter Task Description: ")
                due_date = input("Enter Due Date: ")
                classification_level = input("Enter Classification Level: ")
                user.add_task(task_description, due_date, classification_level)
            
            elif choice == '2':
                user.view_tasks()
            
            elif choice == '3':
                password_check = input("Enter password to view deatils: ")
                user.view_sensitive_details(password_check)
            
            elif choice == '4':
                print("Existing...")
                break
            else:
                print("Invalid choice. Please try again. ")
if __name__ == "__main__":
    main()

        

        
    

    