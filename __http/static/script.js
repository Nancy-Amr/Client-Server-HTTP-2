// HEAD Request for resource metadata
document.getElementById('send-head-request').addEventListener('click', function () {
    const resourceUrl = document.getElementById('resource-url').value;

    if (!resourceUrl) {
        alert('Please enter a resource URL.');
        return;
    }

    fetch(resourceUrl, { method: 'HEAD' })
        .then(response => {
            // Build a summary of headers
            const headers = response.headers;
            let headerText = 'Resource Metadata:\n\n';

            // Check availability
            headerText += `Status: ${response.status} ${response.statusText}\n`;

            // Get size (if available)
            if (headers.has('content-length')) {
                headerText += `Size: ${headers.get('content-length')} bytes\n`;
            } else {
                headerText += `Size: Not specified\n`;
            }

            // Get last modification date (if available)
            if (headers.has('last-modified')) {
                headerText += `Last Modified: ${headers.get('last-modified')}\n`;
            } else {
                headerText += `Last Modified: Not specified\n`;
            }

            // Get content type (if available)
            if (headers.has('content-type')) {
                headerText += `Content Type: ${headers.get('content-type')}\n`;
            } else {
                headerText += `Content Type: Not specified\n`;
            }

            document.getElementById('response-headers').textContent = headerText;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('response-headers').textContent = `Error: ${error.message}`;
        });
});

document.getElementById('upload-file').addEventListener('click', function() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file to upload.');
        return;
    }

    const fileName = file.name;
    fetch(`/upload/${fileName}`, {
        method: 'PUT',
        body: file,
    })
        .then(response => response.text())
        .then(data => {
            document.getElementById('upload-response').textContent = `File "${fileName}" uploaded successfully.\nResponse: ${data}`;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('upload-response').textContent = `Error: ${error.message}`;
        });
});

document.getElementById('delete-file').addEventListener('click', function() {
    const filename = document.getElementById('delete-input').value;

    if (!filename) {
        alert('Please enter the filename to delete.');
        return;
    }

    fetch(`/upload/${filename}`, { method: 'DELETE' })
        .then(response => response.text())
        .then(data => {
            document.getElementById('delete-response').textContent = `Delete Response:\n${data}`;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('delete-response').textContent = `Error: ${error.message}`;
        });
});

document.getElementById('submit-body').addEventListener('click', function() {
    const bodyContent = document.getElementById('request-body').value;

    fetch('/resource', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: bodyContent,
    })
        .then(response => response.text())
        .then(data => {
            document.getElementById('response-content').textContent = `Response:\n${data}`;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('response-content').textContent = `Error: ${error.message}`;
        });
});
