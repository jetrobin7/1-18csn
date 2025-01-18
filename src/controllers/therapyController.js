const Therapy = require('../models/therapy'); // Import the Therapy model

// Fetch therapies to display on the page
const fetchTherapies = async (req, res) => {
    try {
        const therapies = await Therapy.find({});
        res.status(200).json({ therapies }); // Return therapies as JSON
    } catch (err) {
        console.error('Error fetching therapies:', err);
        res.status(500).json({ error: 'Unable to fetch therapies' });
    }
};

// Add a new therapy
const addTherapy = async (req, res) => {
    try {
        // Find the latest csnCourseCode in the database
        const lastTherapy = await Therapy.findOne().sort({ csnCourseCode: -1 });

        // Determine the new course code
        const lastCourseCodeNumber = lastTherapy
            ? parseInt(lastTherapy.csnCourseCode.slice(3), 10) // Extract the numeric part after 'CSN'
            : 0; // Default to 0 if no entries exist
        const newCourseCode = lastCourseCodeNumber + 1;

        // Create the new therapy with incremented course code
        const newTherapy = new Therapy({
            csnCourseCode: `CSN${newCourseCode.toString().padStart(3, '0')}`, // Format as 'CSN001'
            name: req.body.name,
            description: req.body.description,
        });

        // Save the new therapy to the database
        await newTherapy.save();

        // Redirect to the "Types of Therapy" page
        res.redirect('/admin/types_of_therapy'); // Adjust the route as needed
    } catch (err) {
        console.error('Error adding therapy:', err);
        res.status(500).json({ error: 'Error adding therapy' });
    }
};


// Render the Types of Therapy page
const renderTypesOfTherapy = async (req, res) => {
    try {
        const therapies = await Therapy.find({});
        res.render('admin/types_of_therapy', { therapies }); // Pass therapies to the view
    } catch (err) {
        console.error('Error rendering types of therapy page:', err);
        res.status(500).send('Error loading page');
    }
};

module.exports = {
    fetchTherapies,
    addTherapy,
    renderTypesOfTherapy, // Export the new method
};
