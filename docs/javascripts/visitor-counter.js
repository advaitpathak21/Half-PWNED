const counter = document.getElementById('visitor-counter');
async function updateCounter() {
    try {
        let response = await fetch("https://toxxssf4l1.execute-api.us-east-1.amazonaws.com/prod/cloud-resume-counter");
        if (!response.ok) throw new Error('Network response was not ok');
        let data = await response.json();
        if (counter) {
            counter.innerText = data;
        }
    } catch (error) {
        console.error('Error fetching visitor count:', error);
    }
}
updateCounter();