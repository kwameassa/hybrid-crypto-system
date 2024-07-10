function encryptAndUpload() {
    const fileInput = document.getElementById('fileInput');
    const fileList = fileInput.files;
    const fileListContainer = document.getElementById('fileList');
    const encryptionMethod = document.getElementById('encryptionMethod').value;
    const keyBits = document.getElementById('keyBits').value; // Get selected key bits
    const startTime = Date.now(); // Record start time for encryption

    // Validate key size for RSA
    if (encryptionMethod === 'RSA/AES' && keyBits < 1024) {
        alert('RSA key size must be at least 1024 bits');
        return;
    }

    // Clear previous file list
    fileListContainer.innerHTML = '';

    // Keep track of the number of completed files
    let completedFiles = 0;
    let allFilesCompleted = false;

    // Iterate through selected files
    for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const listItem = document.createElement('div');
        const progress = document.createElement('progress');
        progress.value = 0;
        progress.max = 100;
        listItem.appendChild(progress); // Add progress bar to the list item
        fileListContainer.appendChild(listItem);

        // Encrypt and upload the file using Python backend
        encryptAndUploadFile(file, listItem, progress, encryptionMethod, keyBits, () => {
            completedFiles++;

            // Check if all files are completed
            if (completedFiles === fileList.length) {
                allFilesCompleted = true;
                showCompletionMessage();
            }
        });
    }

    function showCompletionMessage() {
        // Display a success message with total time
        if (allFilesCompleted) {
            const endTime = Date.now();
            const totalTime = (endTime - startTime) / 1000; // Total time in seconds
            const successMessage = document.createElement('div');
            successMessage.textContent = `Encryption and upload completed. Total time: ${totalTime.toFixed(2)} seconds.`;
            fileListContainer.appendChild(successMessage);
        }
    }
}

// Function to communicate with Python backend for encryption and upload
function encryptAndUploadFile(file, listItem, progress, encryptionMethod, keyBits, onComplete) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('encryption_method', encryptionMethod);
    formData.append('key_bits', keyBits);

    // Use fetch API to send data to Python backend
    fetch('/encrypt', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        // Simulate progress with random intervals
        simulateProgress(progress, () => {
            if (data.error) {
                listItem.textContent = `Error: ${data.error}`; // Update list item text with error
            } else {
                listItem.textContent = `Uploaded: ${file.name}`; // Update list item text
            }
            onComplete(); // Callback function to indicate completion
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

// Function to simulate progress
function simulateProgress(progress, onComplete) {
    const totalTime = Math.random() * 5000 + 1000; // Random time between 1 and 6 seconds
    let elapsedTime = 0;
    const interval = 100;

    const progressInterval = setInterval(() => {
        elapsedTime += interval;
        progress.value = (elapsedTime / totalTime) * 100;

        if (elapsedTime >= totalTime) {
            clearInterval(progressInterval);
            progress.value = 100;
            onComplete();
        }
    }, interval);
}
