

### Submitting Pull Requests
1. Go to the [pwnsheet repository](https://github.com/0x8e5afe/pwnsheet) and click the "Fork" button in the top-right corner.
2. Clone your fork: click on the green button "Code" on the newly created fork and copy the HTTPS url (https://github.com/YOUR_USERNAME/pwnsheet.git), and use it to clone it in your local directory
```bash
# Clone your forked repository (replace YOUR_USERNAME with your GitHub username)
git clone https://github.com/YOUR_USERNAME/pwnsheet.git
cd pwnsheet
```
3. **Set Up the Upstream Remote** that allows you to keep your fork synchronized with the original repository:
``` bash
# Add the original repository as "upstream"
git remote add upstream https://github.com/0x8e5afe/pwnsheet.git

# Verify your remotes
git remote -v
```
You should see something like:
``` bash
origin    https://github.com/YOUR_USERNAME/pwnsheet.git (fetch)
origin    https://github.com/YOUR_USERNAME/pwnsheet.git (push)
upstream  https://github.com/0x8e5afe/pwnsheet.git (fetch)
upstream  https://github.com/0x8e5afe/pwnsheet.git (push)
````
4. **Create a Feature Branch**: never work directly on the main branch:
```bash
# Make sure you're on main
git checkout main

# Pull latest changes from upstream
git pull upstream main

# Create a new branch for your feature
git checkout -b feature/your-feature-name
```
Good branch naming examples:
- `feature/add-web-shells-section`
- `fix/parameter-highlighting-bug`
- `docs/improve-installation-guide`
5. **Test the Application Locally**
	```bash
	# Start a local server
	python3 -m http.server 8000
	```
	Open http://localhost:8000 in your browser across different browsers and test your changes. Sometimes you can also try to open it in a private window to make sure your changes are correctly taken. 
6. **Make Your Changes**
	Based on the project structure, here are common contribution areas:
	**For adding/modifying pentesting content:**
	- Edit markdown files in the `notes/` directory
	- Follow the existing parameter format: `<PARAMETER_NAME>` or `{{PARAMETER_NAME}}`
	- Keep commands practical and commonly used
	**For improving functionality:**
	- `scripts/constants.js` - Add shared state or templates
	- `scripts/utils.js` - Add helper functions
	- `scripts/modals.js` - Modify modal behaviors
	- `scripts/content.js` - Change markdown rendering
	- `scripts/main.js` - Adjust global event handlers
	**For UI improvements:**
	- `styles.css` - Modify styling and themes
	- `index.html` - Adjust structure
7. **Test Your Changes Thoroughly**
	- Test across different browsers (Chrome, Firefox, Safari)
	- Verify parameter replacement works correctly
	- Check that progress tracking persists
	- Ensure mobile responsiveness if you changed UI
8. **Commit Your Changes**
	Use clear, descriptive commit messages:
```bash
# Stage your changes
git add .

# Commit with a descriptive message
git commit -m "Add post-exploitation Windows commands section"
```
Good commit message examples:
- "Add reverse shell one-liners for Python and Ruby"
- "Fix parameter highlighting in nested code blocks"
- "Update README with macOS installation instructions"

9. **Push to Your Fork**
````bash
git push origin feature/your-feature-name
````

10. **Create a Pull Request**
	1. Go to your fork on GitHub (`https://github.com/YOUR_USERNAME/pwnsheet`)
	2. You'll see a banner suggesting to create a pull request
	3. Click "Compare & pull request"
	4. Fill in the PR description:
	   - Explain what changes you made
	   - Why the changes are beneficial
	   - Any testing you performed
	   - Screenshots if UI-related

**Example PR Description:**
```
## Description
Added a comprehensive web shells section to the Post Exploitation phase with:
- PHP web shells
- ASP.NET web shells
- JSP web shells
- Parameter support for target URL and file path

## Testing
- Verified all commands render correctly
- Tested parameter replacement functionality
- Checked mobile responsiveness

## Related Issue
Closes #123 (if applicable)
````

	Click "Create pull request"

### Keeping Your Fork Updated
Before starting new work, always sync with upstream:
```bash
# Switch to main branch
git checkout main

# Fetch upstream changes
git fetch upstream

# Merge upstream changes
git merge upstream/main

# Push to your fork
git push origin main
```
### Best Practices

1. **One feature per branch** - Don't mix multiple unrelated changes
2. **Test before submitting** - Make sure everything works
3. **Follow existing code style** - Match the project's conventions
4. **Write clear commits** - Future contributors will thank you
5. **Be responsive** - Address any feedback on your PR promptly
6. **Start small** - Fix a typo or add a small feature first
