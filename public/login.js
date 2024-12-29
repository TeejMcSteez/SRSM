const loginForm = document.getElementById('loginForm');

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault(); // Prevent the form from refreshing the page

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    if (response.ok) {
      const data = await response.json();
      // sessionStorage.setItem('authToken', data.token); Deprecated dont wanna use session storage and only wanna use cookie storage for proper handling, I cant access the session storage from the server side DUMBASS
      alert('Login successful! Redirecting...');
      window.location.href = data.redirect; // Redirect to your main page
    } else {
      const error = await response.json();
      alert(`Error: ${error.message}`);
    }
  } catch (err) {
    alert('An error occurred. Please try again.');
    console.error(err);
  }
});