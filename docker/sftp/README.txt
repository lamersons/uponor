To test sftp service integration with uponors LDAP(for managing folder structure and users from AD) please provide
the following environment:

1. Please create random OU/folder structure on uponors AD similar to attached screenshot,and return to me with sftp base DN path.
2. Assign a user(gives permissions to access parent and child folders on sftp) under random OU folders.

Some notes :
1. MUST be not more than one user per OU, is there a reason to have more ?
2. users attributes in AD: "first_name", "full_name", "display_name" and "login_name" MUST match !!!!!!!!
User password or other attributes and settings are ignored.
