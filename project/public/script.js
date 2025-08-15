document.getElementById('commandForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const command = document.getElementById('command').value;
    const responseDiv = document.getElementById('response');
    
    try {
        const response = await fetch('/api', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ command }),
        });
        const result = await response.json();
        responseDiv.innerText = result.message || 'حدث خطأ';
    } catch (error) {
        responseDiv.innerText = 'خطأ في الاتصال بالخادم: ' + error.message;
    }
});