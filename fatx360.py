import multiprocessing
import os
import re
import shutil
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk

# Use 75% of available cores (minimum 2) to avoid overwhelming the system
CPU_COUNT = max(2, int(multiprocessing.cpu_count() * 0.75))


def is_fatx_compatible(name):
    """Check if a filename is FATX compatible without changing it."""
    # Check length (including extension)
    if len(name) > 42:
        return False

    # Check for invalid characters
    valid_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()."
    )
    if not all(char in valid_chars or char.isspace() for char in name):
        return False

    return True


def make_fatx_compatible(name, is_directory=False):
    filename, extension = os.path.splitext(name)
    # Remove invalid characters but keep spaces
    filename = re.sub(r"[^\w\s()]", "", filename)

    if is_directory:
        # For directories: Keep beginning, truncate from end if needed
        max_length = 42 - len(extension)
        if len(filename) > max_length:
            filename = filename[:max_length]
    else:
        # For files: Keep end, truncate from beginning if needed
        max_length = 42 - len(extension)
        if len(filename) > max_length:
            filename = filename[-max_length:]

    return filename + extension


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("FATX360 v1.3")
        self.master.geometry("500x550")
        self.pack(fill=tk.BOTH, expand=True)
        self.all_selected = False
        self.total_items = 0
        self.processed_items = 0
        self.cancel_flag = False
        self.max_depth = 10  # Maximum depth for the slider
        self.create_widgets()

    def create_widgets(self):
        self.create_menu()

        dir_frame = ttk.Frame(self)
        dir_frame.pack(fill=tk.X, padx=10, pady=5)

        self.dir_entry = ttk.Entry(dir_frame)
        self.dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.select_dir_button = ttk.Button(
            dir_frame, text="Select Directory", command=self.select_directory
        )
        self.select_dir_button.pack(side=tk.RIGHT)

        # Add radio button frame after dir_frame
        self.mode_frame = ttk.LabelFrame(self, text="Operation Mode")
        self.mode_frame.pack(fill=tk.X, padx=10, pady=5)

        self.operation_mode = tk.StringVar(value="copy")
        self.copy_radio = ttk.Radiobutton(
            self.mode_frame,
            text="Copy to new directory",
            variable=self.operation_mode,
            value="copy",
        )
        self.copy_radio.pack(side=tk.LEFT, padx=5)

        self.inplace_radio = ttk.Radiobutton(
            self.mode_frame,
            text="Modify in place",
            variable=self.operation_mode,
            value="inplace",
        )
        self.inplace_radio.pack(side=tk.LEFT, padx=5)

        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.select_all_button = ttk.Button(
            list_frame, text="Select All", command=self.toggle_select_all
        )
        self.select_all_button.pack(side=tk.TOP, anchor=tk.W)

        self.listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE)
        self.listbox.pack(fill=tk.BOTH, expand=True)

        options_frame = ttk.Frame(self)
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        self.top_level_var = tk.BooleanVar()
        self.top_level_check = ttk.Checkbutton(
            options_frame, text="Rename top-level folders", variable=self.top_level_var
        )
        self.top_level_check.pack(side=tk.TOP, anchor=tk.W)

        self.subfolders_var = tk.BooleanVar()
        self.subfolders_check = ttk.Checkbutton(
            options_frame,
            text="Rename subfolders",
            variable=self.subfolders_var,
            command=self.toggle_depth_slider,
        )
        self.subfolders_check.pack(side=tk.TOP, anchor=tk.W)

        # Depth slider
        self.depth_frame = ttk.Frame(options_frame)
        self.depth_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        self.depth_label = ttk.Label(self.depth_frame, text="Subfolder depth:")
        self.depth_label.pack(side=tk.LEFT)
        self.depth_var = tk.IntVar(value=self.max_depth)
        self.depth_slider = ttk.Scale(
            self.depth_frame,
            from_=1,
            to=self.max_depth,
            orient=tk.HORIZONTAL,
            variable=self.depth_var,
            length=200,
            command=self.update_depth_label,
        )
        self.depth_slider.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.depth_value_label = ttk.Label(self.depth_frame, text=str(self.max_depth))
        self.depth_value_label.pack(side=tk.LEFT)
        self.depth_frame.pack_forget()  # Initially hidden

        self.files_var = tk.BooleanVar()
        self.files_check = ttk.Checkbutton(
            options_frame, text="Rename files", variable=self.files_var
        )
        self.files_check.pack(side=tk.TOP, anchor=tk.W)

        self.rename_button = ttk.Button(
            options_frame, text="Rename Selected", command=self.rename_selected
        )
        self.rename_button.pack(side=tk.TOP, pady=5)

        progress_frame = ttk.Frame(self)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)

        self.progress = ttk.Progressbar(
            progress_frame, orient=tk.HORIZONTAL, length=100, mode="determinate"
        )
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = ttk.Label(progress_frame, text="0 / 0")
        self.progress_label.pack(side=tk.RIGHT)

        self.cancel_button = ttk.Button(
            self, text="Cancel", command=self.cancel_operation, state=tk.DISABLED
        )
        self.cancel_button.pack(pady=5)

    def create_menu(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Select Directory", command=self.select_directory)
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.dir_entry.delete(0, tk.END)
        self.dir_entry.insert(0, self.directory)
        self.update_listbox()

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        try:
            for item in os.listdir(self.directory):
                self.listbox.insert(tk.END, item)
            self.all_selected = False
            self.select_all_button.config(text="Select All")
        except PermissionError:
            messagebox.showerror(
                "Permission Error", "Cannot access the selected directory."
            )
        except FileNotFoundError:
            messagebox.showerror(
                "Directory Not Found", "The selected directory does not exist."
            )

    def toggle_select_all(self):
        if self.all_selected:
            self.listbox.selection_clear(0, tk.END)
            self.select_all_button.config(text="Select All")
        else:
            self.listbox.selection_set(0, tk.END)
            self.select_all_button.config(text="Deselect All")
        self.all_selected = not self.all_selected

    def toggle_depth_slider(self):
        if self.subfolders_var.get():
            self.depth_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        else:
            self.depth_frame.pack_forget()

    def update_depth_label(self, *args):
        self.depth_value_label.config(text=str(self.depth_var.get()))

    def rename_selected(self):
        selected_indices = self.listbox.curselection()
        selected_items = [self.listbox.get(i) for i in selected_indices]
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select items to rename.")
            return

        # Ask for confirmation if modifying in place
        if self.operation_mode.get() == "inplace":
            if not messagebox.askyesno(
                "Confirm Operation",
                "This will modify the files in place. Are you sure you want to continue?",
            ):
                return
            dest_dir = self.directory
        else:
            dest_dir = filedialog.askdirectory(
                title="Select Destination Folder for Renamed Items"
            )
            if not dest_dir:
                return

        self.progress["value"] = 0
        self.rename_button["state"] = "disabled"
        self.cancel_button["state"] = "normal"
        self.cancel_flag = False

        self.total_items = self.count_total_items(selected_items)
        self.processed_items = 0
        self.update_progress_label()

        thread = threading.Thread(
            target=self.rename_items_thread, args=(selected_items, dest_dir)
        )
        thread.start()

    def count_total_items(self, items):
        total = 0
        for item in items:
            full_path = os.path.join(self.directory, item)
            if os.path.isdir(full_path):
                for root, dirs, files in os.walk(full_path):
                    total += len(files)
            else:
                total += 1
        return total

    def rename_items_thread(self, items, dest_dir):
        is_copy_mode = self.operation_mode.get() == "copy"

        if is_copy_mode:
            renamed_dir = os.path.join(dest_dir, "RENAMED")
            try:
                os.makedirs(renamed_dir, exist_ok=True)
            except PermissionError:
                self.show_error(
                    "Permission Error", "Cannot create the RENAMED directory."
                )
                self.finish_operation()
                return
        else:
            renamed_dir = dest_dir

        # Create a list of work items
        work_items = []
        for item in items:
            full_path = os.path.join(self.directory, item)
            work_items.append(
                {
                    "path": full_path,
                    "is_dir": os.path.isdir(full_path),
                    "dest_dir": renamed_dir,
                    "rename_top_level": self.top_level_var.get(),
                    "rename_subfolders": self.subfolders_var.get(),
                    "rename_files": self.files_var.get(),
                    "is_copy_mode": is_copy_mode,
                }
            )

        # Process items in parallel using a thread pool
        with ThreadPoolExecutor(max_workers=CPU_COUNT) as executor:
            futures = []
            for work in work_items:
                if self.cancel_flag:
                    break

                if work["is_dir"]:
                    future = executor.submit(
                        self.process_directory,
                        work["path"],
                        work["dest_dir"],
                        work["rename_top_level"],
                        work["rename_subfolders"],
                        work["rename_files"],
                        work["is_copy_mode"],
                    )
                else:
                    future = executor.submit(
                        self.process_file,
                        work["path"],
                        work["dest_dir"],
                        work["rename_files"],
                        work["is_copy_mode"],
                    )
                futures.append(future)

            # Wait for all tasks to complete
            for future in futures:
                try:
                    if self.cancel_flag:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    future.result()  # This will raise any exceptions that occurred
                except PermissionError as e:
                    self.show_error("Permission Error", str(e))
                except shutil.Error as e:
                    self.show_error("Copy Error", str(e))
                except OSError as e:
                    self.show_error("OS Error", str(e))

        if not self.cancel_flag:
            msg = (
                "Selected items have been renamed and copied to the RENAMED folder."
                if is_copy_mode
                else "Selected items have been renamed in place."
            )
            self.show_success("Rename Complete", msg)
        self.finish_operation()

    def process_directory(
        self,
        src_dir,
        dest_parent_dir,
        rename_top_level,
        rename_subfolders,
        rename_files,
        is_copy_mode,
        current_depth=0,
    ):
        try:
            # First check if renaming is actually needed
            orig_name = os.path.basename(src_dir)
            new_dir_name = (
                make_fatx_compatible(orig_name, is_directory=True)
                if rename_top_level
                or (rename_subfolders and current_depth < self.depth_var.get())
                else orig_name
            )

            # Only use the new name if it's different and needs to be changed
            needs_rename = not is_fatx_compatible(orig_name)
            final_name = new_dir_name if needs_rename else orig_name
            new_dir_path = os.path.join(dest_parent_dir, final_name)

            if is_copy_mode:
                os.makedirs(new_dir_path, exist_ok=True)
            elif needs_rename:  # Only rename if necessary
                os.rename(src_dir, new_dir_path)
                src_dir = new_dir_path

            # Process directory contents
            with ThreadPoolExecutor(max_workers=CPU_COUNT) as executor:
                futures = []

                for root, dirs, files in os.walk(src_dir):
                    if self.cancel_flag:
                        return

                    rel_path = os.path.relpath(root, src_dir)
                    new_root = os.path.join(
                        new_dir_path if is_copy_mode else dest_parent_dir, rel_path
                    )

                    if (
                        rename_subfolders
                        and current_depth < self.depth_var.get()
                        and root != src_dir
                    ):
                        new_name = make_fatx_compatible(
                            os.path.basename(root), is_directory=True
                        )
                        if new_name != os.path.basename(root):
                            new_root = os.path.join(os.path.dirname(new_root), new_name)
                            if not is_copy_mode:
                                os.rename(root, new_root)

                    if is_copy_mode:
                        os.makedirs(new_root, exist_ok=True)

                    # Process files in parallel
                    for file in files:
                        if self.cancel_flag:
                            return
                        src_file = os.path.join(root, file)
                        future = executor.submit(
                            self.process_file,
                            src_file,
                            new_root,
                            rename_files,
                            is_copy_mode,
                        )
                        futures.append(future)

                    break  # Only process top level

                # Wait for all file operations to complete
                for future in futures:
                    if self.cancel_flag:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    future.result()

        except Exception as e:
            self.show_error("Directory Processing Error", str(e))

    def process_file(self, src_file, dest_dir, rename_file, is_copy_mode):
        orig_name = os.path.basename(src_file)
        new_name = (
            make_fatx_compatible(orig_name, is_directory=False)
            if rename_file
            else orig_name
        )

        # Only proceed with rename if the name actually needs to change
        needs_rename = rename_file and not is_fatx_compatible(orig_name)
        final_name = new_name if needs_rename else orig_name
        new_path = os.path.join(dest_dir, final_name)

        if is_copy_mode:
            shutil.copy2(src_file, new_path)
        elif needs_rename:  # Only rename if necessary
            os.rename(src_file, new_path)

        self.processed_items += 1
        self.update_progress()

    def update_progress(self):
        progress_value = (self.processed_items / self.total_items) * 100
        self.progress["value"] = progress_value
        self.update_progress_label()

    def update_progress_label(self):
        self.progress_label.config(text=f"{self.processed_items} / {self.total_items}")

    def cancel_operation(self):
        self.cancel_flag = True
        self.cancel_button["state"] = "disabled"
        self.show_info("Operation Cancelled", "The renaming operation was cancelled.")
        self.reset_interface()

    def finish_operation(self):
        self.rename_button["state"] = "normal"
        self.cancel_button["state"] = "disabled"
        self.cancel_flag = False
        self.reset_interface()

    def reset_interface(self):
        # Reset progress bar
        self.progress["value"] = 0
        self.progress_label.config(text="0 / 0")

        # Reset selection
        self.listbox.selection_clear(0, tk.END)
        self.all_selected = False
        self.select_all_button.config(text="Select All")

        # Reset checkboxes
        self.top_level_var.set(False)
        self.subfolders_var.set(False)
        self.files_var.set(False)

        # Hide depth slider
        self.depth_frame.pack_forget()

        # Reset depth slider value
        self.depth_var.set(self.max_depth)
        self.update_depth_label()

        # Reset counters
        self.total_items = 0
        self.processed_items = 0

    def show_error(self, title, message):
        self.master.after(0, lambda: messagebox.showerror(title, message))

    def show_success(self, title, message):
        self.master.after(0, lambda: messagebox.showinfo(title, message))

    def show_info(self, title, message):
        self.master.after(0, lambda: messagebox.showinfo(title, message))


root = tk.Tk()
app = Application(master=root)
app.mainloop()
