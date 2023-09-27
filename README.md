# Password Manager Documentation

## Introduction
The Password Manager application is designed to help users securely manage their passwords. This document provides an overview of the application's features, usage instructions, known issues, and upcoming improvements.

## Features
- **Add Password:** Allows users to add a new password entry to the database.
- **Delete Password:** Enables users to remove a password entry from the database.
- **View Archive:** Displays archived passwords stored in the database.
- **Generate Password:** Generates a random password with a specified length.
- **View Log:** Provides a log of application activities.
- **Save Password:** Saves a newly added password entry.
- **Cancel:** Cancels the current operation and returns to the home screen.

## Usage
### Add Password
1. Click on the "Add Password" button.
2. Fill in the required information:
   - Username
   - Password
   - Confirm Password
   - Website URL
3. Click the "Save Password" button to save the new password.

### Delete Password
1. Click on the "Delete Password" button.
2. Enter the Website URL of the password to delete.
3. Click the "Delete Password" button to remove the password.

### View Archive
- Click on the "View Archive" button to display archived passwords.

### Generate Password
1. Click on the "Generate Password" button.
2. Enter the desired password length.
3. Click the "Generate" button to create a random password.

### View Log
- Click on the "View Log" button to view application logs.

### Save Password
1. After adding a new password, a confirmation dialog will appear.
2. Click "Yes" to save the password or "No" to discard it.

## Known Issues
- If the website URL provided is shorter than 4 characters, the application may throw an exception.

## Upcoming Improvements
- Future updates will include enhancements to the user interface for improved usability and aesthetics.

## Updates
- **[09/26/2023]:** Improved the user interface with new button styles and animations.

## Project Repository
- The base project can be found in the [CodeAnarchist/Password-Manager](https://github.com/CodeAnarchist/Password-Manager) repository.
- For more detailed information, including how password encryption and storage are handled, please refer to the base project's documentation.