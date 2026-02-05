- Precedence
- ![](/attachments/Pasted-image-20250205155717.png)
- The Default Domain Policy is the default GPO that is automatically created and linked to the domain

- Let's look at another example using the Group Policy Management Console on a Domain Controller. In this image, we see several GPOs. The `Disabled Forced Restarts` GPO will have precedence over the `Logon Banner` GPO since it would be processed last. Any settings configured in the `Disabled Forced Restarts` GPO could potentially override settings in any GPOs higher up in the hierarchy (including those linked to the `Corp` OU).
![image](https://academy.hackthebox.com/storage/modules/74/gpo_precedence.png)

- `Default Domain Policy` takes precedence over all GPOs at all levels
- `Block Inheritance` - policies higher up will not be applied
- When a new GPO is created, the settings are not automatically applied right away. Windows performs periodic Group Policy updates, which by default is done every 90 minutes with a randomized offset of +/- 30 minutes for users and computers.
