package com.system.RegisterationSystem.student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/student")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );
    @GetMapping("/{id}")
    public Student getStudentById(@PathVariable Integer id){
        return STUDENTS.stream()
                .filter(student -> id.equals(student.studentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Student " + id + " does not exists"
                ));
    }
}
