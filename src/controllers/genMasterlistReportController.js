const Student = require('../models/student');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

// Controller function to handle generating the masterlist report
exports.generateMasterlistReport = async (req, res) => {
    try {
        const { fromDate, toDate, gender } = req.body;

        // Build the query
        let query = {};
        if (fromDate && toDate) {
            query.intakeDate = {
                $gte: new Date(fromDate),
                $lte: new Date(toDate),
            };
        }
        if (gender) {
            query.gender = gender;
        }

        // Fetch students from the database
        const students = await Student.find(query, {
            csnNo: 1,
            surname: 1,
            givenName: 1,
            middleName: 1,
            gender: 1,
            contactNumber: 1,
            emailAddress: 1,
            diagnosis: 1,
        }).lean();

        // Ensure the reports directory exists
        const reportsDir = path.join(__dirname, '../public/reports');
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        // Generate the PDF
        const filePath = path.join(reportsDir, 'Student_Masterlist_Report.pdf');
        const doc = new PDFDocument({ margin: 40, layout: 'landscape', size: 'legal' });

        // Pipe the PDF to a write stream
        const writeStream = fs.createWriteStream(filePath);
        doc.pipe(writeStream);

        // Add logo and header
        const logoPath = path.join(__dirname, '../public/images/csn logo.png');
        if (fs.existsSync(logoPath)) {
            doc.image(logoPath, 40, 40, { width: 50 });
            doc.image(logoPath, doc.page.width - 90, 40, { width: 50 });
        }
        doc.fontSize(16).text('Paranaque Center', { align: 'center' });
        doc.fontSize(12).text('Contact: 123-456-7890 | Email: info@organization.com', { align: 'center' });
        doc.moveDown();

        // Title
        doc.fontSize(14).text('Student Masterlist Report', { align: 'center', underline: true });
        doc.moveDown();

        // Table header
        doc.fontSize(10).font('Helvetica-Bold');
        doc.text('CSN NO', 40, doc.y, { continued: true });
        doc.text('Name', 145, doc.y, { continued: true });
        doc.text('Gender', 300, doc.y, { continued: true });
        doc.text('Contact No.', 380, doc.y, { continued: true });
        doc.text('Email', 480, doc.y, { continued: true });
        doc.text('Diagnosis', 600);

        doc.moveTo(40, doc.y).lineTo(doc.page.width - 40, doc.y).stroke();
        doc.moveDown(0.5);

        // Table content
        doc.font('Helvetica');
        students.forEach((student) => {
            const name = `${student.surname}, ${student.givenName}${student.middleName ? ' ' + student.middleName : ''}`;
            const diagnosis = Array.isArray(student.diagnosis) ? student.diagnosis.join(', ') : 'N/A';

            doc.text(student.csnNo, 40, doc.y, { continued: true });
            doc.text(name, 100, doc.y, { continued: true });
            doc.text(student.gender, 225, doc.y, { continued: true });
            doc.text(student.contactNumber || 'N/A', 325, doc.y, { continued: true });
            doc.text(student.emailAddress || 'N/A', 380, doc.y, { continued: true });
            doc.text(diagnosis, 600);
        });

        // Finalize the PDF
        doc.end();

        writeStream.on('finish', () => {
            res.download(filePath, 'Student_Masterlist_Report.pdf', (err) => {
                if (err) {
                    console.error('Error downloading PDF:', err);
                    return res.status(500).send('Could not generate the report');
                } else {
                    fs.unlink(filePath, (unlinkErr) => {
                        if (unlinkErr) {
                            console.error('Error deleting PDF file:', unlinkErr);
                        }
                    });
                }
            });
        });

        writeStream.on('error', (error) => {
            console.error('Error writing PDF file:', error);
            res.status(500).send('An error occurred while writing the report.');
        });
    } catch (error) {
        console.error('Error generating masterlist report:', error);
        res.status(500).send('An error occurred while generating the report.');
    }
};
