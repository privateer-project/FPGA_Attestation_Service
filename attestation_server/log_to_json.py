import json
import os
import tempfile
import time
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# ... (save_data_to_json_file function from before) ...
def save_data_to_json_file(data_to_save, filepath):
    # ... (implementation from before) ...
    # Ensure os.replace uses filepath, not the global DATA_FILE_PATH
    # if DATA_FILE_PATH is different from filepath argument
    try:
        file_dir = os.path.dirname(filepath)
        if not file_dir: file_dir = "."
        if not os.path.exists(file_dir): os.makedirs(file_dir, exist_ok=True)
        fd, temp_file_path = tempfile.mkstemp(suffix='.tmp', prefix=os.path.basename(filepath) + '_', dir=file_dir)
        
        # logging.info(f"Writing data to temporary file: {temp_file_path}")
        print(f"Writing data to temporary file: {temp_file_path}")
        
        with os.fdopen(fd, 'w') as tmp_file:
            json.dump(data_to_save, tmp_file, indent=4)
        os.replace(temp_file_path, filepath) # Use the filepath argument here

        # logging.info(f"Data successfully saved to {filepath}")
        print(f"Data successfully saved to {filepath}")
        
    except IOError as e:
        logging.error(f"IOError saving data to {filepath}: {e}")
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            try: os.remove(temp_file_path); logging.info(f"Removed temporary file {temp_file_path} after error.")
            except OSError as e_rem: logging.error(f"Error removing temporary file {temp_file_path}: {e_rem}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while saving data to {filepath}: {e}")
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            try: os.remove(temp_file_path)
            except OSError: pass
