# 200 - Create a virtual environment for Python

Suggestion: create a python virtual environment for this project. See the [documentation](https://docs.python.org/3/library/venv.html).

We'll create a virtual environment for Python now, like so:

## Creating a Python Virtual Environment

A virtual environment is an isolated Python environment that allows you to manage dependencies for specific projects without affecting your system Python installation.

### Method 1: Using `venv` (Recommended)

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Verify the virtual environment is active
# You should see (venv) in your terminal prompt
which python
# Should show: /path/to/your/project/venv/bin/python

# Navigate to the directory where requirements.txt is located

# Install packages in the virtual environment
pip install -r requirements.txt

# Deactivate when done
deactivate
```

### Method 2: Using `virtualenv`

```bash
# Install virtualenv if not already installed
pip install virtualenv

# Create a virtual environment
virtualenv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Deactivate when done
deactivate
```

### Method 3: Using `conda` (if you have Anaconda/Miniconda)

```bash
# Create a virtual environment with specific Python version
conda create -n myenv python=3.11

# Activate the environment
conda activate myenv

# Install packages
conda install package_name
# or
pip install package_name

# Deactivate when done
conda deactivate
```

### Best Practices

1. **Always use virtual environments** for Python projects
2. **Name your virtual environment** `venv` or something descriptive
3. **Add `venv/` to `.gitignore`** to avoid committing the environment
4. **Use `requirements.txt`** to track dependencies:
   ```bash
   pip freeze > requirements.txt
   ```
5. **Recreate environment** from requirements:
   ```bash
   pip install -r requirements.txt
   ```

### Troubleshooting

- **Permission errors**: Use `python -m venv venv` instead of `virtualenv venv`
- **Activation not working**: Check your shell (bash, zsh, cmd, PowerShell)
- **Package conflicts**: Create a fresh virtual environment
- **Path issues**: Use absolute paths or ensure you're in the project directory