$(document).ready(function() {
    // Edit Profile Button Click Event
    $('#edit-profile-btn').click(function() {
        // Show the edit profile form
        $('#edit-profile-form').removeClass('hidden');
    });

    // Profile Picture Upload Preview
    $('#profile_picture').change(function(event) {
        const fileInput = event.target;
        const previewImage = $('#profile-picture-preview')[0];

        if (fileInput.files && fileInput.files[0]) {
            const reader = new FileReader();
            reader.onload = function(e) {
                previewImage.src = e.target.result;
            };
            reader.readAsDataURL(fileInput.files[0]);
        }
    });

    // Form Submission
    $('#profile-form').submit(function(event) {
        event.preventDefault();

        // Extract form data
        const formData = new FormData(this);

        // Send form data to the server using AJAX
        $.ajax({
            url: '/profile',
            type: 'POST',
            data: formData,
            processData: false, // Important for file upload
            contentType: false, // Important for file upload
            success: function(response) {
                // Handle successful response (e.g., show success message)
                console.log('Profile updated successfully!');
                // Refresh the page after successful submission
                location.reload();
            },
            error: function(xhr, status, error) {
                // Handle error response (e.g., show error message)
                console.error('Error updating profile:', error);
            }
        });

        // Hide the edit profile form after submission
        $('#edit-profile-form').addClass('hidden');
    });
});
